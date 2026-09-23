"""An independent master, pointed at our outstation, reporting what it read.

Runs under Python 3.10 against ``dnp3-python``, which wraps opendnp3. That is a
separately developed C++ implementation, so what it reads is evidence about this
library rather than about our reading of the specification. A peer written from
the same understanding would share the same misreadings, which is the whole
reason this file exists and is not written with ``py1815``.

The upstream stack is end-of-life, which disqualifies it as a dependency and not
as a witness: a frame it parses is a frame that was correct in 2022, and the
wire format has not moved.

Exits non-zero, loudly, on anything it cannot verify.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import sys
import time

from dnp3_python.dnp3station.master import MyMaster
from pydnp3.opendnp3 import GroupVariationID

#: Must match ``interop/outstation.py``.
EXPECTED = [10, -20, 30, 40, 50]

GROUP_ANALOG_INPUT = 30
VARIATION_INT32_WITH_FLAG = 1


def fail(message: str) -> None:
    print(f"probe: FAIL {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    master = MyMaster(
        outstation_ip=args.host,
        port=args.port,
        master_id=args.master_address,
        outstation_id=args.outstation_address,
    )
    master.start()

    try:
        deadline = time.time() + args.timeout
        while time.time() < deadline and not master.is_connected:
            time.sleep(0.5)
        if not master.is_connected:
            fail(f"no connection to {args.host}:{args.port} within {args.timeout}s")
        print("probe: connected")

        # Ask for the variation this outstation serves. The default scan list
        # leads with group 30 variation 6 -- double-precision float -- and an
        # outstation that answers a specific request with a different variation
        # is not one a master should have to accommodate.
        scan = [GroupVariationID(GROUP_ANALOG_INPUT, VARIATION_INT32_WITH_FLAG)]

        values: dict[int, float] = {}
        while time.time() < deadline:
            master.send_scan_all_request(gv_ids=scan)
            time.sleep(1.0)
            values = {}
            for index in range(len(EXPECTED)):
                value = master.get_val_by_group_variation_index(
                    GROUP_ANALOG_INPUT, VARIATION_INT32_WITH_FLAG, index
                )
                if _numeric(value):
                    values[index] = float(value)
            if len(values) >= len(EXPECTED):
                break

        if not values:
            fail("the integrity poll returned no analog inputs")

        print(f"probe: read {values}")
        # Quality is not checked here, and cannot be with this peer: its
        # database stores bare scalars (``DbPointVal = Union[float, int, bool]``)
        # and discards the flag octet before any caller sees it. Index 3 is
        # served offline with COMM_LOST set, which this job therefore cannot
        # observe -- the wire-level tests in the unit suite are what pin it.
        # Closing that gap needs a peer that exposes quality, not a change here.
        for index, expected in enumerate(EXPECTED):
            if index not in values:
                fail(f"index {index} missing from the response")
            if float(values[index]) != float(expected):
                fail(f"index {index} read {values[index]}, expected {expected}")

        print(f"probe: OK, {len(EXPECTED)} analog inputs match")
    finally:
        master.shutdown()


def _numeric(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


if __name__ == "__main__":
    main()
