"""The outstation under test, serving a fixed point map.

Run by the interoperability job, not by the test suite. It exists so the master
on the other side has something deterministic to check against: the values below
are arbitrary, and the point is that they are known, distinct, and include a
negative one and a point marked offline.

It also accepts controls, over points chosen so that a master can see both
answers in one request: some it will operate, and one it deliberately will
not.

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
from py1815.objects import AnalogPoint, AnalogVariation, analog_flags, analog_range
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
