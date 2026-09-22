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

from dnp3_python.dnp3station.master_new import MyMasterNew

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

    master = MyMasterNew(
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

        values: dict[int, float] = {}
        while time.time() < deadline:
            master.send_scan_all_request()
            time.sleep(1.0)
            database = master.get_db_by_group_variation(
                group=GROUP_ANALOG_INPUT, variation=VARIATION_INT32_WITH_FLAG
            )
            values = _flatten(database)
            if len(values) >= len(EXPECTED):
                break

        if not values:
            fail("the integrity poll returned no analog inputs")

        print(f"probe: read {values}")
        for index, expected in enumerate(EXPECTED):
            if index not in values:
                fail(f"index {index} missing from the response")
            if float(values[index]) != float(expected):
                fail(f"index {index} read {values[index]}, expected {expected}")

        print(f"probe: OK, {len(EXPECTED)} analog inputs match")
    finally:
        master.shutdown()


def _flatten(database: object) -> dict[int, float]:
    """Pull ``{index: value}`` out of whatever shape the master hands back.

    The upstream returns a nested mapping keyed by group-variation, and its
    exact shape has changed across releases. Rather than pin a version's
    internals, this walks what it is given and takes the innermost numeric
    mapping. A shape it cannot read is a failure the caller reports, not a
    silently empty result.
    """
    if isinstance(database, dict):
        if database and all(isinstance(key, int) for key in database):
            return {int(k): float(v) for k, v in database.items() if _numeric(v)}
        for value in database.values():
            found = _flatten(value)
            if found:
                return found
    return {}


def _numeric(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


if __name__ == "__main__":
    main()
