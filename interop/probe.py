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
import contextlib
import faulthandler
import os
import sys
import threading
import time

from dnp3_python.dnp3station.master import MyMaster
from pydnp3.opendnp3 import GroupVariationID

#: Must match ``interop/outstation.py``.
EXPECTED = [10, -20, 30, 40, 50]

#: How long a clean shutdown is given before the probe leaves without it.
_SHUTDOWN_GRACE = 2.0

GROUP_ANALOG_INPUT = 30
VARIATION_INT32_WITH_FLAG = 1


def say(message: str) -> None:
    """Print and flush.

    Flushed because this is a diagnostic first and a check second: when a run
    hangs, the last line printed is the whole of the evidence, and
    block-buffered output does not survive the cancellation that ends it.
    """
    print(f"probe: {message}", flush=True)


def leave(code: int) -> None:
    """Exit without waiting for the upstream to unwind.

    ``master.shutdown()`` joins threads inside a C++ library, and a probe that
    has already reached its verdict must not be able to hang on that. The
    verdict is flushed; nothing after it is worth waiting for.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def _shutdown_without_waiting(master: object) -> None:
    """Ask the master to shut down, and do not depend on it finishing.

    ``shutdown()`` joins threads inside a C++ library. Suppressing exceptions
    around it does nothing about a hang, which is the failure that matters here:
    a probe that has already printed its verdict would sit in the join until the
    step timeout and be reported as failed despite having succeeded.

    So it runs on a daemon thread, joined briefly out of politeness. ``leave``
    ends the process either way, and a daemon thread does not outlive it.
    """
    thread = threading.Thread(target=_quiet_shutdown, args=(master,), daemon=True)
    thread.start()
    thread.join(timeout=_SHUTDOWN_GRACE)
    if thread.is_alive():
        say("shutdown did not return; leaving anyway")


def _quiet_shutdown(master: object) -> None:
    with contextlib.suppress(Exception):
        master.shutdown()  # type: ignore[attr-defined]


def fail(message: str) -> None:
    print(f"probe: FAIL {message}", file=sys.stderr, flush=True)
    leave(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    # Whatever hangs next should say where. faulthandler prints every thread's
    # stack, including the ones with no Python frame, which is what identified
    # the deadlock this file used to have. Set well beyond the work below so it
    # fires only on a hang, and before the workflow's own step bound so the dump
    # survives.
    faulthandler.dump_traceback_later(args.timeout + 30.0, exit=True)

    master = MyMaster(
        outstation_ip=args.host,
        port=args.port,
        master_id=args.master_address,
        outstation_id=args.outstation_address,
    )
    master.start()

    try:
        deadline = time.time() + args.timeout
        # Deliberately not master.is_connected.
        #
        # That property reads channel_statistic twice, and channel_statistic
        # calls GetStatistics() once per dictionary key, so each read is six
        # calls into the C++ channel. Polling it every half second deadlocks
        # against the stack's own worker thread, which needs the GIL to deliver
        # its logging callbacks into Python while this thread holds the GIL
        # inside a call that does not release it. The process then hangs with no
        # output, and the loop above never re-evaluates its own deadline because
        # the block is inside the condition.
        #
        # Reproduced locally at 8 hangs in 15 runs with two CPUs, and 0 in 15
        # with this poll removed. Nothing else here calls into the channel
        # outside a bounded retry, and the scan loop below establishes
        # connectivity by succeeding: a genuine failure to connect arrives as
        # "the integrity poll returned no analog inputs" once the deadline
        # expires, which is a less specific message than the one this replaced
        # and an actual verdict rather than a hang.
        say(f"started, polling {args.host}:{args.port} for up to {args.timeout:.0f}s")

        # Ask for the variation this outstation serves. The default scan list
        # leads with group 30 variation 6 -- double-precision float -- and an
        # outstation that answers a specific request with a different variation
        # is not one a master should have to accommodate.
        scan = [GroupVariationID(GROUP_ANALOG_INPUT, VARIATION_INT32_WITH_FLAG)]

        values: dict[int, float] = {}
        attempt = 0
        while time.time() < deadline:
            attempt += 1
            say(f"scan {attempt}, {deadline - time.time():.0f}s left")
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

        say(f"read {values}")
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

        say(f"OK, {len(EXPECTED)} analog inputs match")
    finally:
        _shutdown_without_waiting(master)
    leave(0)


def _numeric(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


if __name__ == "__main__":
    main()
