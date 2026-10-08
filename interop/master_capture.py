"""Record this library's master reading an outstation, for the dissectors to read.

Run by the parsers job against ``interop/outstation.py``. The master is driven
through its JSON service with a capture file, which is how
``py1815-master serve --capture FILE`` writes one, so the file the dissectors
read is the one a user of the master gets.

The master settles the outstation as it does on connecting (unsolicited
reporting disabled, the restart indication cleared, an integrity poll that
confirms the events it carries), then polls for events and by each class,
writes the time, reads named points and reads output status. Wireshark and
Suricata then judge both directions: the requests and confirmations this
master built, and the responses the outstation sent.

The script also checks that the file written as the frames crossed the wire
is, octet for octet, the file the service's ``capture`` operation exports
from the trace.

``--summary`` records how many application fragments went each way, for the
validators to compare with what each dissector found.

Exits non-zero if any request was not answered, or the two captures differ.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import pathlib
import sys
import time
from collections import Counter
from typing import Any

from py1815.application import FunctionCode
from py1815.master.capture import CaptureFile
from py1815.master.service import Service
from py1815.master.trace import RECEIVED, SENT

NAME = "fixture"

#: What the master asks for after its startup tasks, as service messages.
STEPS: list[tuple[str, dict[str, Any]]] = [
    ("scan", {"kind": "events"}),
    ("scan", {"kind": "class1"}),
    ("scan", {"kind": "class2"}),
    ("scan", {"kind": "class3"}),
    ("scan", {"kind": "class0"}),
    ("write_time", {}),
    ("read", {"points": {"ai": [0, 2, 3]}}),
    ("scan", {"kind": "outputs"}),
    ("scan", {"kind": "integrity"}),
]

#: The analog inputs the named read asks for, and the values the fixture serves there.
NAMED = {0: 10, 2: 30, 3: 40}


async def add(service: Service, args: argparse.Namespace) -> None:
    """Add the outstation, retrying while it is still starting."""
    deadline = time.monotonic() + args.timeout
    params = {
        "name": NAME,
        "host": args.host,
        "port": args.port,
        "outstation_address": args.outstation_address,
        "master_address": args.master_address,
        "reconnect": None,
    }
    while True:
        answer = await service.handle({"op": "add", "params": params})
        if answer["ok"]:
            return
        if answer["error"]["kind"] != "connection" or time.monotonic() > deadline:
            raise SystemExit(f"master-capture: cannot add the outstation: {answer['error']}")
        await service.handle({"op": "remove", "outstation": NAME})
        await asyncio.sleep(0.5)


async def ask(service: Service, op: str, params: dict[str, Any]) -> dict[str, Any]:
    """Send one message and return its result. Exit if it was refused or not answered."""
    answer = await service.handle({"op": op, "outstation": NAME, "params": params})
    if not answer["ok"]:
        raise SystemExit(f"master-capture: {op} {params} was refused: {answer['error']}")
    result: dict[str, Any] = answer["result"]
    if result.get("outcome", "complete") != "complete":
        raise SystemExit(f"master-capture: {op} {params} ended {result['outcome']}")
    print(f"master-capture: {op} {params}: {result.get('object_count', 0)} objects", flush=True)
    return result


def count_fragments(service_trace: Any) -> dict[str, int]:
    """Count the application fragments in the trace, by direction and kind."""
    functions: Counter[str] = Counter()
    for entry in service_trace.since(0):
        if entry.application is None:
            continue
        functions[f"{entry.direction}:{entry.application['function']}"] += 1
    confirms = functions[f"{SENT}:{FunctionCode.CONFIRM.name}"]
    requests = sum(n for key, n in functions.items() if key.startswith(f"{SENT}:")) - confirms
    replies = sum(n for key, n in functions.items() if key.startswith(f"{RECEIVED}:"))
    return {"application_requests": requests, "confirms": confirms, "application_replies": replies}


async def run(args: argparse.Namespace) -> int:
    pcap = pathlib.Path(args.pcap)
    service = Service(allow_control=True, capture=CaptureFile(pcap))
    try:
        await add(service, args)
        await ask(service, "idle", {})
        for op, params in STEPS:
            result = await ask(service, op, params)
            if op == "read":
                # The fixture answers any read of group 30 with every point it
                # serves, so the points named are a part of what comes back.
                read = {item["index"]: item["value"] for item in result["objects"]}
                if not NAMED.items() <= read.items():
                    print(f"master-capture: FAIL the named read returned {read}", file=sys.stderr)
                    return 1
        # Nothing is due once idle, so no frame follows the export.
        await ask(service, "idle", {})
        exported = base64.b64decode((await ask(service, "capture", {}))["pcap"])
        outstation = service.master[NAME]
    finally:
        await service.close()

    written = pcap.read_bytes()
    if written != exported:
        print(
            "master-capture: FAIL the file written as frames crossed the wire is not the "
            "capture the trace exports",
            file=sys.stderr,
        )
        return 1

    counts = count_fragments(outstation.trace)
    print(f"master-capture: wrote {len(written)} octets to {pcap}: {counts}", flush=True)
    if args.summary:
        pathlib.Path(args.summary).write_text(json.dumps(counts, indent=1), encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    parser.add_argument("--pcap", required=True, help="the capture file to write")
    parser.add_argument(
        "--summary", help="record the application fragments sent and received, as JSON"
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait to connect")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
