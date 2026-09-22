"""The outstation under test, serving a fixed point map.

Run by the interoperability job, not by the test suite. It exists so the master
on the other side has something deterministic to check against: the values below
are arbitrary, and the point is that they are known, distinct, and include a
negative one and a point marked offline.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence

from py1815.application import ObjectHeader
from py1815.objects import AnalogPoint, AnalogVariation, analog_flags, analog_range
from py1815.server import OutstationServer
from py1815.session import Session

#: What the master must read back. Distinct values so a mis-indexed read is
#: visible rather than plausible, a negative one so sign handling is exercised,
#: and one point offline so the quality octet is not uniformly 0x01.
POINTS = [
    AnalogPoint(10),
    AnalogPoint(-20),
    AnalogPoint(30),
    AnalogPoint(40, analog_flags(online=False, comm_lost=True)),
    AnalogPoint(50),
]

EXPECTED = [10, -20, 30, 40, 50]


class FixedProvider:
    """Answers every read with the same analog range."""

    def read(self, headers: Sequence[ObjectHeader]) -> bytes:
        return analog_range(0, POINTS, variation=AnalogVariation.INT32_WITH_FLAG)


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="outstation: %(message)s")

    session = Session(
        FixedProvider(),
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
