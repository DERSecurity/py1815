"""The outstation under test, serving a fixed point map and a fixed event buffer.

Run by the interoperability job, not by the test suite. It exists so the master
on the other side has something deterministic to check against: the values below
are arbitrary, and the point is that they are known, distinct, and include a
negative one and a point marked offline.

It also accepts controls, over points chosen so that a master can see both
answers in one request: some it will operate, and one it deliberately will
not.

And it holds events, in all three classes, carrying values no static read of
this fixture ever returns and none of which repeats across classes. A peer
reporting one of those numbers can only have read it from the buffers, and only
from the class it belongs to.

The Rust master reads them, a class at a time, and checks each class against
its own events. The function code sweep reads them too, and its traffic is
dissected by Wireshark and Suricata -- so the wire format and a master's
interpretation of it are both checked by implementations that are not this one.

The C++ probe scans group 30 variation 1 and reads no class. It stays that way
deliberately, and the event plan says why.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence

from py1815.application import ObjectHeader, object_header
from py1815.control import (
    GROUP_ANALOG_OUTPUT_STATUS,
    GROUP_BINARY_OUTPUT_STATUS,
    CommandStatus,
    ControlRelayOutputBlock,
    OperationType,
    encode_analog_output_status,
    encode_binary_output_status,
)
from py1815.events import EventBuffers, EventClass
from py1815.objects import (
    AnalogPoint,
    AnalogVariation,
    BinaryPoint,
    analog_flags,
    analog_range,
)
from py1815.server import OutstationServer
from py1815.session import Control, Session, UnknownObject

#: What the master must read back. Distinct values so a mis-indexed read is
#: visible rather than plausible, and a negative one so sign handling is
#: exercised. ``probe.py`` carries the same list, which the two virtual
#: environments make unavoidable.
EXPECTED = [10, -20, 30, 40, 50]

#: The index served offline, so the quality octet is not uniformly 0x01. The
#: probe cannot see this -- its master discards quality -- so the unit suite
#: checks it instead.
OFFLINE_INDEX = 3

#: Derived from EXPECTED rather than written twice: two lists in one file where
#: only one is read is the arrangement that drifts, because editing the
#: decorative one changes nothing.
POINTS = [
    AnalogPoint(
        value,
        analog_flags(online=False, comm_lost=True) if index == OFFLINE_INDEX else analog_flags(),
    )
    for index, value in enumerate(EXPECTED)
]


#: Events this fixture holds, per class, as ``(index, value)``.
#:
#: The values are deliberately unlike anything ``EXPECTED`` holds. A master that
#: reports 101 cannot have got it from a static read, which is the whole of what
#: the event cases prove: that the class it asked for was answered from the
#: buffers rather than from the point map.
#:
#: The values are distinct across the classes as well as from the point map,
#: and that -- not the indices -- is what catches a class being mixed up. The
#: indices are deliberately reused: class 1 holds analog 0 and 1 and a binary
#: event at index 0 too, because a peer that keys events by index alone should
#: be seen to do so rather than accommodated.
EVENTS = {
    EventClass.CLASS_1: ((0, 101.0), (1, 102.0)),
    EventClass.CLASS_2: ((2, 203.0),),
    EventClass.CLASS_3: ((3, 304.0),),
}

#: A binary event, in class 1 behind the analog ones, so that a class 1 read
#: comes back as two blocks of different groups in the order the points changed.
#: A peer that gathers them by type instead of keeping that order is telling its
#: operator a different story about when things happened.
BINARY_EVENT_INDEX = 0


#: Recorded once at startup rather than driven from a timer. The peers need
#: something deterministic to assert against, and a clock that keeps adding
#: events makes every assertion a race -- a master reading twice would see a
#: different answer for reasons that have nothing to do with the protocol.
#: Liveness is not what these jobs are testing.
def seeded_events() -> EventBuffers:
    """The buffers this fixture serves, filled and ready to read."""
    buffers = EventBuffers()
    stamp = 0
    for event_class, points in EVENTS.items():
        for index, value in points:
            stamp += 1
            buffers.record_analog(
                index, AnalogPoint(value), event_class=event_class, timestamp_ms=stamp
            )
    buffers.record_binary(
        BINARY_EVENT_INDEX,
        BinaryPoint(state=True),
        event_class=EventClass.CLASS_1,
        timestamp_ms=stamp + 1,
    )
    return buffers


#: Binary outputs this fixture will operate.
CONTROLLABLE_BINARY = (0, 1)

#: One it will not, on purpose. A master that commands this index gets
#: ``NOT_SUPPORTED`` against that object while the others in the same request
#: succeed, which is the per-object answer D14 promises and the thing a
#: fragment-level refusal cannot demonstrate.
UNCONTROLLABLE_BINARY = 9

#: Analog outputs this fixture will operate. Variation 1 is a 32-bit setpoint,
#: which exceeds Subset Level 2 and is exactly the case the design document
#: names: a 50 kW value does not fit the 16-bit point Level 2 offers.
CONTROLLABLE_ANALOG = (0,)


class FixedControls:
    """Operates the points it owns, refuses the rest, and remembers the result.

    The state is what makes the readback worth having: a master that commands a
    point and then reads group 10 or 40 sees what it did, rather than a constant
    that would look identical if the control had been dropped.
    """

    def __init__(self) -> None:
        self.binary = dict.fromkeys(CONTROLLABLE_BINARY, False)
        self.analog = dict.fromkeys(CONTROLLABLE_ANALOG, 0.0)

    def select(self, controls: Sequence[Control]) -> list[CommandStatus]:
        """Whether each could be operated. Nothing moves here."""
        return [self._verdict(item) for item in controls]

    def operate(self, controls: Sequence[Control]) -> list[CommandStatus]:
        statuses = [self._verdict(item) for item in controls]
        for item, status in zip(controls, statuses, strict=True):
            if status is CommandStatus.SUCCESS:
                self._apply(item)
        return statuses

    def _verdict(self, item: Control) -> CommandStatus:
        command = item.command
        if isinstance(command, ControlRelayOutputBlock):
            if item.index not in self.binary:
                return CommandStatus.NOT_SUPPORTED
            if command.queued:
                # Bit 4 is obsolete in IEEE 1815-2012 and required to be zero. A
                # master that sets it is asking for behavior the standard
                # withdrew, which is malformed rather than unimplemented.
                return CommandStatus.FORMAT_ERROR
            if command.operation not in (OperationType.LATCH_ON, OperationType.LATCH_OFF):
                # Pulses need a timer this fixture has no reason to own.
                return CommandStatus.NOT_SUPPORTED
            return CommandStatus.SUCCESS
        if item.index not in self.analog:
            return CommandStatus.NOT_SUPPORTED
        return CommandStatus.SUCCESS

    def _apply(self, item: Control) -> None:
        command = item.command
        if isinstance(command, ControlRelayOutputBlock):
            self.binary[item.index] = command.operation is OperationType.LATCH_ON
        else:
            self.analog[item.index] = command.value

    def status_objects(self, group: int) -> bytes:
        """A readback block: an object header, then the points it covers.

        The header is not optional. A provider hands the session a response body
        and the session forwards it unchanged, so objects returned bare would
        have a master reading the first status octet as an object group.
        """
        if group == GROUP_BINARY_OUTPUT_STATUS:
            indices = sorted(self.binary)
            variation = 2
            body = b"".join(
                encode_binary_output_status(state=self.binary[index]) for index in indices
            )
        else:
            indices = sorted(self.analog)
            variation = 1
            body = b"".join(
                encode_analog_output_status(self.analog[index], variation) for index in indices
            )
        header = object_header(group, variation, start=indices[0], stop=indices[-1])
        return header + body


#: What this fixture serves: its analog inputs, the output status points a
#: master reads back after commanding, and the class objects a class-0 read asks
#: for. Anything else is refused, so the unknown-object path is a thing the
#: sweep can reach rather than a branch nothing exercises.
SERVED_GROUPS = frozenset({30, 60, GROUP_BINARY_OUTPUT_STATUS, GROUP_ANALOG_OUTPUT_STATUS})


class FixedProvider:
    """Answers reads for the groups it serves, and refuses the rest."""

    def __init__(self, controls: FixedControls) -> None:
        self._controls = controls

    def read(self, headers: Sequence[ObjectHeader]) -> bytes:
        unknown = sorted({h.group for h in headers} - SERVED_GROUPS)
        if unknown:
            raise UnknownObject(f"this fixture serves no group {unknown}")

        asked = {h.group for h in headers}
        outputs = asked & {GROUP_BINARY_OUTPUT_STATUS, GROUP_ANALOG_OUTPUT_STATUS}
        wants_inputs = bool(asked - outputs)

        # One block per group asked for, rather than a branch that picks one
        # kind. A request naming an output status group beside group 30, or a
        # class 0 read alongside either, is a master combining a readback with
        # an input read -- and answering only one of them drops data the master
        # asked for without saying so.
        body = b"".join(self._controls.status_objects(group) for group in sorted(outputs))
        if wants_inputs:
            body += analog_range(0, POINTS, variation=AnalogVariation.INT32_WITH_FLAG)
        return body


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="outstation: %(message)s")

    controls = FixedControls()
    session = Session(
        FixedProvider(controls),
        control_provider=controls,
        events=seeded_events(),
        outstation_address=args.outstation_address,
        master_address=args.master_address,
    )
    server = OutstationServer(session, bind=f"127.0.0.1:{args.port}")
    await server.start()
    try:
        await asyncio.Event().wait()
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
