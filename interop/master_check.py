"""Read and command an independent outstation with the py1815 master.

Run by the interoperability job against an outstation this project did not
write: ``interop/opendnp3_outstation.py`` (opendnp3, C++) or
``interop/rust-outstation`` (the ``dnp3`` crate, Rust). Both serve the fixture
below and print every control and time write they receive.

This script checks two things:

- What the master decodes matches what the outstation serves.
- What the outstation says it received matches what the master sent. That is
  read from the outstation's log, so it does not depend on this library's own
  decoding.

Exits non-zero if any check fails, after running all of them.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import pathlib
import sys
import time

from py1815.application import FunctionCode, IINBit
from py1815.control import CommandStatus
from py1815.master import ALL, Master, Outstation, PointType, Tasks

# ---- The fixture. Must match the two independent outstations.

BINARY_INPUTS = [True, False, True, False, True]
ANALOG_INPUTS = [10, -20, 30, 40, 50]
ANALOG_OFFLINE_INDEX = 3
ANALOG_COUNT = 600
COUNTERS = [100, 200]
OUTPUT_COUNT = 3
ANALOG_OUTPUT_LIMIT_INDEX = 2
MIRROR_BINARY_INPUT = 1
MIRROR_ANALOG_INPUT = 1

ONLINE = 0x01
COMM_LOST = 0x04

STARTUP = ["disable_unsolicited", "clear_restart", "write_time", "integrity", "enable_unsolicited"]


#: How many checks a complete run makes. A run that makes fewer stopped part
#: way, for example after an early return in a section, and fails even if
#: nothing it checked failed. Change this when a check is added or removed.
EXPECTED_CHECKS = 68


class Checks:
    """Runs named checks, prints each result, and counts the checks and failures."""

    def __init__(self) -> None:
        self.ran = 0
        self.failed = 0

    def check(self, name: str, passed: bool, detail: object = "") -> None:
        self.ran += 1
        if passed:
            print(f"ok    {name}", flush=True)
        else:
            self.failed += 1
            print(f"FAIL  {name}: {detail}", flush=True)

    def equal(self, name: str, actual: object, expected: object) -> None:
        self.check(name, actual == expected, f"got {actual!r}, expected {expected!r}")


class Log:
    """The outstation's log file, read for the lines it prints."""

    def __init__(self, path: pathlib.Path) -> None:
        self._path = path

    def lines(self) -> list[str]:
        try:
            text = self._path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return [line.strip() for line in text.splitlines()]

    async def has(self, line: str, *, timeout: float = 5.0) -> bool:
        """Wait up to ``timeout`` seconds for a line to appear."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if line in self.lines():
                return True
            await asyncio.sleep(0.1)
        return line in self.lines()

    def count(self, line: str) -> int:
        return self.lines().count(line)

    def time_written(self) -> int | None:
        for line in self.lines():
            if line.startswith("time written "):
                return int(line.rsplit(" ", 1)[1])
        return None


async def until(condition, *, timeout: float = 10.0) -> bool:
    """Wait up to ``timeout`` seconds for ``condition()`` to be true."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.05)
    return bool(condition())


async def connect(master: Master, args: argparse.Namespace, seen: list) -> Outstation:
    """Connect, retrying while the outstation is still starting."""
    deadline = time.monotonic() + args.timeout
    while True:
        try:
            return await master.add(
                "peer",
                host=args.host,
                port=args.port,
                outstation_address=args.outstation_address,
                master_address=args.master_address,
                tasks=Tasks(enable_unsolicited=(1, 2, 3)),
                reconnect=None,
                on_exchange=seen.append,
            )
        except OSError:
            if time.monotonic() > deadline:
                raise
            await asyncio.sleep(0.5)


async def check_startup(checks: Checks, lab: Outstation, seen: list, log: Log) -> None:
    """The automatic startup tasks, as the outstation saw them."""
    await asyncio.wait_for(lab.idle(), 30)
    startup = [exchange for exchange in seen if exchange.task is not None]
    checks.equal("startup tasks run in order", [e.task for e in startup][:5], STARTUP)
    checks.check(
        "every startup request is answered",
        all(exchange.complete for exchange in startup),
        [(e.task, e.outcome.value) for e in startup],
    )
    integrity = next((e for e in startup if e.task == "integrity"), None)
    if integrity is not None:
        checks.check(
            "integrity poll spans more than one fragment",
            len(integrity.fragments) > 1,
            f"{len(integrity.fragments)} fragment(s)",
        )
        checks.equal("integrity poll decodes completely", list(integrity.undecoded), [])

    answer = await lab.read(counters=ALL)
    checks.check("restart indication is cleared", not answer.iin.is_set(IINBit.DEVICE_RESTART))
    checks.check("need-time indication is cleared", not answer.iin.is_set(IINBit.NEED_TIME))
    written = log.time_written()
    now = round(time.time() * 1000)
    checks.check(
        "outstation received the current time",
        written is not None and abs(written - now) < 60_000,
        f"outstation logged {written}, now is {now}",
    )


def check_values(checks: Checks, lab: Outstation) -> None:
    """What the integrity poll stored, against the fixture."""
    store = lab.store
    binary = store.points(PointType.BINARY_INPUT)
    checks.equal(
        "binary input values",
        [binary[i].value for i in sorted(binary)],
        BINARY_INPUTS,
    )
    checks.check(
        "binary inputs are online",
        all(value.flags & ONLINE for value in binary.values()),
        {i: value.flags for i, value in binary.items()},
    )

    analog = store.points(PointType.ANALOG_INPUT)
    checks.equal("analog input count", len(analog), ANALOG_COUNT)
    checks.equal(
        "first analog input values",
        [analog[i].value for i in range(len(ANALOG_INPUTS)) if i in analog],
        ANALOG_INPUTS,
    )
    checks.check(
        "remaining analog inputs hold their index",
        all(analog[i].value == i for i in range(len(ANALOG_INPUTS), ANALOG_COUNT) if i in analog),
        "an analog input above index 4 does not hold its index",
    )
    offline = analog.get(ANALOG_OFFLINE_INDEX)
    checks.check(
        "offline analog input has COMM_LOST and not ONLINE",
        offline is not None and offline.flags & COMM_LOST and not offline.flags & ONLINE,
        None if offline is None else hex(offline.flags),
    )
    checks.check(
        "other analog inputs are online",
        all(v.flags & ONLINE for i, v in analog.items() if i != ANALOG_OFFLINE_INDEX),
        "an analog input other than the offline one is not ONLINE",
    )

    counters = store.points(PointType.COUNTER)
    checks.equal("counter values", [counters[i].value for i in sorted(counters)], COUNTERS)
    checks.check(
        "counters are online",
        bool(counters) and all(value.flags & ONLINE for value in counters.values()),
        {i: value.flags for i, value in counters.items()},
    )


async def check_reads(checks: Checks, lab: Outstation) -> None:
    """Reads of named points."""
    answer = await lab.read(analog_inputs=[0, 2, 3], binary_inputs=[4])
    read = {(o.point, o.index): o.value for o in answer.objects}
    checks.equal(
        "read by index returns the points named",
        read,
        {
            (PointType.ANALOG_INPUT, 0): 10,
            (PointType.ANALOG_INPUT, 2): 30,
            (PointType.ANALOG_INPUT, 3): 40,
            (PointType.BINARY_INPUT, 4): True,
        },
    )
    spread = await lab.read(analog_inputs=[5, 300, 301, 599])
    checks.equal(
        "read of scattered indices, some above 255",
        sorted((o.index, o.value) for o in spread.objects),
        [(5, 5), (300, 300), (301, 301), (599, 599)],
    )
    # The same two points asked for as single and as double precision floats:
    # group 30 variations 5 and 6, indices 0 to 1.
    for variation, name in ((5, "single"), (6, "double")):
        floats = await lab.request(FunctionCode.READ, bytes([30, variation, 0x00, 0, 1]))
        checks.equal(
            f"analog inputs read as {name} precision floats",
            [(o.index, o.value, o.variation) for o in floats.objects],
            [(0, 10.0, variation), (1, -20.0, variation)],
        )
    outputs = await lab.scan("outputs")
    statuses = [(o.point, o.index, o.value) for o in outputs.objects]
    expected = [(PointType.BINARY_OUTPUT, i, False) for i in range(OUTPUT_COUNT)] + [
        (PointType.ANALOG_OUTPUT, i, 0) for i in range(OUTPUT_COUNT)
    ]
    checks.equal("output status before any control", statuses, expected)

    # Outstations differ here and both are allowed: opendnp3 sets an error
    # indication (PARAM_ERROR), and the dnp3 crate answers with nothing.
    missing = await lab.read(analog_inputs=[ANALOG_COUNT + 50])
    checks.check(
        "a point that does not exist returns no value",
        missing.complete and not missing.objects,
        [(o.point, o.index, o.value) for o in missing.objects],
    )
    print(f"      (its indications were {missing.iin})", flush=True)
    delay = await lab.request(FunctionCode.DELAY_MEASURE)
    checks.check("delay measurement is answered", delay.complete, delay.outcome.value)


def _statuses(result) -> list:
    return [status.status for status in result.statuses]


async def check_controls(checks: Checks, lab: Outstation, log: Log) -> None:
    """Controls, checked against what the outstation logged."""
    store = lab.store

    result = await lab.operate(binary_outputs={0: True}, mode="select")
    checks.equal(
        "select and operate sends both requests",
        [exchange.function for exchange in result.exchanges],
        [FunctionCode.SELECT, FunctionCode.OPERATE],
    )
    checks.check("select and operate is accepted", result.accepted is True, _statuses(result))
    checks.check(
        "outstation echoed the control unchanged",
        all(status.echoed for status in result.statuses),
        [status.echoed for status in result.statuses],
    )
    checks.check("outstation saw the select", await log.has("control select bo 0 latch_on"))
    checks.check("outstation saw the operate", await log.has("control operate bo 0 latch_on"))
    mirrored = await until(
        lambda: (
            (point := store.binary_input(MIRROR_BINARY_INPUT)) is not None
            and point.value is True
            and point.from_event
        )
    )
    checks.check("unsolicited response reports the mirrored binary input", mirrored)
    checks.check("an unsolicited response was received", len(lab.unsolicited) > 0)

    result = await lab.operate(analog_outputs={0: 250})
    checks.check("direct operate of a 16-bit analog output is accepted", result.accepted is True)
    checks.equal("16-bit variation was used", result.statuses[0].command.variation, 2)
    checks.check("outstation saw 250", await log.has("control operate ao 0 250"))
    mirrored = await until(
        lambda: (
            (point := store.analog_input(MIRROR_ANALOG_INPUT)) is not None and point.value == 250
        )
    )
    checks.check("unsolicited response reports the mirrored analog input", mirrored)

    result = await lab.operate(analog_outputs={1: 70000})
    checks.check("32-bit analog output is accepted", result.accepted is True, _statuses(result))
    checks.equal("32-bit variation was used", result.statuses[0].command.variation, 1)
    checks.check("outstation saw 70000", await log.has("control operate ao 1 70000"))

    result = await lab.operate(analog_outputs={1: -12.5})
    checks.check("float analog output is accepted", result.accepted is True, _statuses(result))
    checks.check("outstation saw -12.5", await log.has("control operate ao 1 -12.5"))

    result = await lab.operate(analog_outputs={1: 0.1}, variation=4)
    checks.check("double analog output is accepted", result.accepted is True, _statuses(result))
    checks.check("outstation saw 0.1", await log.has("control operate ao 1 0.1"))

    for operation in ("pulse_on", "pulse_off", "trip", "close"):
        result = await lab.operate(binary_outputs={2: operation})
        checks.check(f"{operation} is accepted", result.accepted is True, _statuses(result))
        checks.check(
            f"outstation saw {operation}", await log.has(f"control operate bo 2 {operation}")
        )

    result = await lab.operate(binary_outputs={1: True}, mode="direct_no_ack")
    checks.check("no-acknowledge operate reports no verdict", result.accepted is None)
    checks.check(
        "outstation operated the no-acknowledge control",
        await log.has("control operate bo 1 latch_on"),
    )

    result = await lab.operate(binary_outputs={2: False}, analog_outputs={2: 7})
    checks.equal(
        "two controls in one request are both accepted",
        _statuses(result),
        [CommandStatus.SUCCESS, CommandStatus.SUCCESS],
    )
    checks.check(
        "outstation saw both",
        await log.has("control operate bo 2 latch_off") and await log.has("control operate ao 2 7"),
    )

    result = await lab.operate(binary_outputs={7: True}, mode="select")
    checks.equal(
        "select of a missing output is refused", _statuses(result), [CommandStatus.NOT_SUPPORTED]
    )
    checks.check("refused select is reported as not accepted", result.accepted is False)
    checks.check("no operate follows a refused select", result.operated is False)
    await asyncio.sleep(0.5)
    checks.equal("outstation never operated it", log.count("control operate bo 7 latch_on"), 0)

    result = await lab.operate(analog_outputs={ANALOG_OUTPUT_LIMIT_INDEX: 5000})
    checks.equal("out-of-range value is refused", _statuses(result), [CommandStatus.OUT_OF_RANGE])
    checks.check("refusal is reported as not accepted", result.accepted is False)

    outputs = await lab.scan("outputs")
    checks.check(
        "output statuses are online",
        bool(outputs.objects)
        and all(o.flags is not None and o.flags & ONLINE for o in outputs.objects),
        [(o.point, o.index, o.flags) for o in outputs.objects],
    )
    statuses = {(o.point, o.index): o.value for o in outputs.objects}
    checks.equal(
        "output status after the controls",
        statuses,
        {
            (PointType.BINARY_OUTPUT, 0): True,
            (PointType.BINARY_OUTPUT, 1): True,
            (PointType.BINARY_OUTPUT, 2): False,
            (PointType.ANALOG_OUTPUT, 0): 250,
            (PointType.ANALOG_OUTPUT, 1): 0,
            (PointType.ANALOG_OUTPUT, 2): 7,
        },
    )


async def check_event_poll(checks: Checks, lab: Outstation, seen: list) -> None:
    """With unsolicited reporting off, the master polls when events are indicated."""
    disabled = await lab.disable_unsolicited()
    checks.check("unsolicited reporting is disabled", disabled.complete and not disabled.iin.second)
    del seen[:]
    received = len(lab.unsolicited)

    result = await lab.operate(binary_outputs={0: False})
    checks.check("latch off is accepted", result.accepted is True, _statuses(result))
    # The outstation records the event just after it answers the control, so
    # this read is the first response that can indicate it.
    await asyncio.sleep(0.5)
    await lab.read(counters=ALL)
    await asyncio.wait_for(lab.idle(), 15)

    checks.check(
        "master polled for events without being asked",
        any(exchange.task == "events" for exchange in seen),
        [(exchange.task, exchange.function.name) for exchange in seen],
    )
    point = lab.store.binary_input(MIRROR_BINARY_INPUT)
    checks.check(
        "event poll delivered the change",
        point is not None and point.value is False and point.from_event,
        point,
    )
    checks.equal("no unsolicited response arrived while disabled", len(lab.unsolicited), received)
    after = await lab.read(counters=ALL)
    checks.check(
        "no events are left waiting",
        not any(
            after.iin.is_set(bit)
            for bit in (IINBit.CLASS_1_EVENTS, IINBit.CLASS_2_EVENTS, IINBit.CLASS_3_EVENTS)
        ),
        after.iin,
    )


async def run(args: argparse.Namespace) -> int:
    checks = Checks()
    log = Log(args.log)
    seen: list = []
    async with Master() as master:
        lab = await connect(master, args, seen)
        await check_startup(checks, lab, seen, log)
        check_values(checks, lab)
        await check_reads(checks, lab)
        await check_controls(checks, lab, log)
        await check_event_poll(checks, lab, seen)
        counts = dict(lab.counts)
    checks.equal("no request timed out or was abandoned", set(counts) - {"complete", "sent"}, set())
    if checks.ran != EXPECTED_CHECKS:
        print(f"ran {checks.ran} checks, expected {EXPECTED_CHECKS}", flush=True)
        return 1
    if checks.failed:
        print(f"{checks.failed} check(s) failed", flush=True)
        return 1
    print(f"every check passed ({checks.ran})", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    parser.add_argument("--log", type=pathlib.Path, required=True, help="the outstation's log file")
    parser.add_argument("--timeout", type=float, default=30.0, help="seconds to wait to connect")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
