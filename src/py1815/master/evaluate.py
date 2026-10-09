"""Run checks against an outstation, and report how each ended.

What ``py1815-master evaluate`` does: connect to an outstation, carry out the
checks of :mod:`py1815.master.checks`, and print a report with a verdict for
each. A check that writes to the outstation is run only when the run is
allowed to command. The report can also be written as JSON, and the traffic
as a pcap file in which each check's frames can be found by number.

From Python:

.. code-block:: python

    report = await evaluate(outstation, point_map, commanding=True)
    for line in report.lines():
        print(line)

:func:`evaluate` takes a connected :class:`~py1815.master.api.Outstation`.
:func:`evaluate_loopback` runs the same checks against a session in this
process, with no socket and no waiting.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import importlib.metadata
import json
import pathlib
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from py1815.master import bench as benches
from py1815.master.api import Outstation
from py1815.master.bench import DEFAULT_SETTLE, Bench, Check, NoAnswer, Result, Verdict
from py1815.master.capture import CaptureFile
from py1815.master.checks import CATALOG, select
from py1815.master.config import MEGABYTE, MasterConfig, OutstationConfig
from py1815.master.profile import DerProfile
from py1815.master.trace import Entry, Recorder
from py1815.profile import load
from py1815.profile.model import Composition, MapError, PointMap

#: What each verdict is called in the printed report.
_WORDS = {
    Verdict.PASSED: "passed",
    Verdict.FAILED: "FAILED",
    Verdict.NOT_APPLICABLE: "not applicable",
    Verdict.NOT_RUN: "not run",
}


@dataclass(frozen=True)
class Report:
    """How every check of a run ended."""

    #: What was evaluated, as the caller named it.
    outstation: str
    #: When the run began, in seconds since the epoch.
    started: float
    #: Whether the run was allowed to write to the outstation.
    commanding: bool
    #: The edition of the profile tables the checks were read from.
    edition: str
    results: tuple[Result, ...]

    def count(self, verdict: Verdict) -> int:
        """Return how many checks ended with a verdict."""
        return sum(1 for result in self.results if result.verdict is verdict)

    @property
    def failed(self) -> bool:
        """Whether any check failed."""
        return self.count(Verdict.FAILED) > 0

    def describe(self) -> dict[str, Any]:
        """Return the report as a JSON-compatible dict."""
        try:
            version = importlib.metadata.version("py1815")
        except importlib.metadata.PackageNotFoundError:
            version = "unknown"
        began = datetime.datetime.fromtimestamp(self.started, datetime.UTC)
        return {
            "tool": "py1815-master evaluate",
            "version": version,
            "outstation": self.outstation,
            "started": began.isoformat(timespec="seconds"),
            "allow_control": self.commanding,
            "tables": self.edition,
            "summary": {verdict.value: self.count(verdict) for verdict in Verdict},
            "results": [result.describe() for result in self.results],
        }

    def render(self) -> str:
        """Return the report as formatted JSON."""
        return json.dumps(self.describe(), indent=2) + "\n"

    def lines(self) -> list[str]:
        """Return the report as lines of text: a line for each check, then the totals."""
        began = datetime.datetime.fromtimestamp(self.started, datetime.UTC)
        writes = "allowed to write" if self.commanding else "read only"
        lines = [
            f"{self.outstation}, {began.isoformat(timespec='seconds')}, {writes}",
            f"profile tables: {self.edition or 'edition not stated'}",
            "",
        ]
        width = max((len(result.id) for result in self.results), default=0)
        for result in self.results:
            lines.append(f"{result.id:<{width}}  {_WORDS[result.verdict]:<14}  {result.title}")
            indent = " " * (width + 2)
            if result.detail:
                lines.append(f"{indent}{result.detail}")
            lines.extend(f"{indent}note: {note}" for note in result.notes)
            if result.verdict is Verdict.FAILED and result.packets is not None:
                first, last = result.packets
                lines.append(f"{indent}packets {first} to {last} of the capture")
            elif result.verdict is Verdict.FAILED and result.frames is not None:
                lines.append(f"{indent}frames {result.frames[0]} to {result.frames[1]}")
        totals = ", ".join(
            f"{self.count(verdict)} {_WORDS[verdict].lower()}"
            for verdict in Verdict
            if self.count(verdict)
        )
        lines += ["", f"{len(self.results)} checks: {totals or 'none'}"]
        return lines


def _bench(
    point_map: PointMap | DerProfile,
    settle: float,
    curves: int | None,
    device_profile: str | None,
    capture: Any = None,
) -> Bench:
    profile = point_map if isinstance(point_map, DerProfile) else DerProfile(point_map)
    return Bench(
        profile, settle=settle, curves=curves, device_profile=device_profile, capture=capture
    )


async def evaluate(
    outstation: Any,
    point_map: PointMap | DerProfile,
    *,
    checks: Sequence[Check] | None = None,
    commanding: bool = False,
    settle: float = DEFAULT_SETTLE,
    curves: int | None = None,
    device_profile: str | None = None,
    capture: Any = None,
    pause: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> Report:
    """Run checks against a connected outstation, and return the report.

    Args:
        outstation: A connected :class:`~py1815.master.api.Outstation`.
        point_map: The profile's points, as the outstation is expected to serve them.
        checks: The checks to run, in order. Defaults to the whole catalog.
        commanding: Run the checks that write to the outstation. They change
            its settings, enable and disable its functions, and stop and
            start it.
        settle: Seconds to wait for the outstation to reach a state it was
            commanded to.
        curves: How many curves the outstation stores. Found by selecting
            each in turn when not given.
        device_profile: The text of the outstation's Device Profile document.
        capture: The :class:`~py1815.master.capture.Capture` the outstation's
            frames are being written to. Each result then gives the numbers of
            its packets in it.
        pause: Awaited with the seconds of each wait.

    Raises :class:`~py1815.master.bench.NoAnswer` when the outstation does
    not answer the first read.
    """
    bench = _bench(point_map, settle, curves, device_profile, capture)
    started = time.time()
    plan = benches.run_plan(bench, CATALOG if checks is None else checks, commanding=commanding)
    results = await benches.drive_async(outstation, plan, pause)
    name = getattr(outstation, "name", "outstation")
    return Report(str(name), started, commanding, bench.map.edition, results)


def evaluate_loopback(
    loopback: Any,
    point_map: PointMap | DerProfile,
    *,
    checks: Sequence[Check] | None = None,
    commanding: bool = False,
    settle: float = DEFAULT_SETTLE,
    curves: int | None = None,
    device_profile: str | None = None,
    advance: Callable[[float], None] | None = None,
) -> Report:
    """Run checks against a :class:`~py1815.master.loopback.Loopback`, and return the report.

    ``advance`` is called with the seconds of each wait, so the caller can
    move a simulated device forward. Nothing waits in real time.
    """
    bench = _bench(point_map, settle, curves, device_profile)
    started = time.time()
    plan = benches.run_plan(bench, CATALOG if checks is None else checks, commanding=commanding)
    results = benches.drive(loopback, plan, advance or (lambda seconds: None))
    return Report("loopback", started, commanding, bench.map.edition, results)


# ------------------------------------------------------------ the command line


def catalog_lines() -> list[str]:
    """Return the catalog as lines of text: each check's identifier, set and title."""
    width = max(len(check.id) for check in CATALOG)
    lines = []
    for check in CATALOG:
        kind = "writes" if check.commands else "reads"
        lines.append(f"{check.id:<{width}}  {check.group:<14}  {kind:<6}  {check.title}")
    return lines


def _chosen(config: MasterConfig, name: str | None) -> OutstationConfig:
    """Return the outstation to evaluate: the one named, or the only one configured."""
    if name is not None:
        for outstation in config.outstations:
            if outstation.name == name:
                return outstation
        known = ", ".join(each.name for each in config.outstations) or "none"
        raise ValueError(f"no outstation is named {name!r}; the configuration has {known}")
    if len(config.outstations) == 1:
        return config.outstations[0]
    if not config.outstations:
        raise ValueError(
            "no outstation to evaluate: give one with --outstation NAME=HOST:PORT or in --config"
        )
    names = ", ".join(each.name for each in config.outstations)
    raise ValueError(f"name the outstation to evaluate: {names}")


async def _run(
    config: MasterConfig,
    chosen: OutstationConfig,
    point_map: PointMap,
    checks: Sequence[Check],
    device_profile: str | None,
) -> Report:
    """Connect, run the checks, and close the connection."""
    tasks = chosen.tasks if config.allow_control else chosen.tasks.reading_only()
    outstation = Outstation(
        chosen.name,
        host=chosen.host,
        port=chosen.port,
        outstation_address=chosen.outstation_address,
        master_address=chosen.master_address,
        response_timeout=chosen.response_timeout,
        read_retries=chosen.read_retries,
        connect_timeout=chosen.connect_timeout,
        tls=None if chosen.tls is None else chosen.tls.context(),
        server_name=None if chosen.tls is None else chosen.tls.server_name,
        confirm=chosen.confirm,
        tasks=tasks,
        manual=chosen.manual,
        reconnect=None,
    )
    capture: CaptureFile | None = None
    recorder: Recorder | None = None
    if config.capture is not None:
        capture = CaptureFile(
            config.capture,
            max_bytes=round(config.capture_max_mb * MEGABYTE),
            keep=config.capture_keep,
        )
        recorder = Recorder(capture, outstation.trace, port=chosen.port)
        failed = False

        def on_frame(entry: Entry) -> None:
            # A capture file that cannot be written ends the capture, not the run.
            nonlocal failed
            if failed or recorder is None:
                return
            try:
                recorder.record(entry)
            except OSError as error:
                failed = True
                print(f"the capture stopped: {error}", file=sys.stderr)

        outstation.trace.listeners.append(on_frame)
    try:
        await outstation.connect(wait=config.connect_wait or None)
        await outstation.idle()
        report = await evaluate(
            outstation,
            point_map,
            checks=checks,
            commanding=config.allow_control,
            settle=config.evaluate.settle,
            curves=config.evaluate.curves,
            device_profile=device_profile,
            capture=capture,
        )
    finally:
        await outstation.close()
        if recorder is not None and capture is not None:
            try:
                recorder.close()
                capture.close()
            except OSError as error:
                print(f"the capture could not be closed: {error}", file=sys.stderr)
    where = f"{chosen.name} at {chosen.host}:{chosen.port}, outstation {chosen.outstation_address}"
    return Report(where, report.started, report.commanding, report.edition, report.results)


def run(args: argparse.Namespace, config: MasterConfig) -> int:
    """Evaluate an outstation as ``args`` and ``config`` say. Return the exit status.

    0 when no check failed, 1 when one did, and 2 when the run could not be
    made: a setting that cannot be used, no tables, or no answer.
    """
    if args.list:
        for line in catalog_lines():
            print(line)
        return 0
    try:
        chosen = _chosen(config, args.name)
        checks = select(config.evaluate.checks)
        point_map = load.load(config.tables, Composition())
        device_profile = None
        if chosen.device_profile is not None:
            device_profile = pathlib.Path(chosen.device_profile).read_text(encoding="utf-8")
    except (MapError, ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    try:
        report = asyncio.run(_run(config, chosen, point_map, checks, device_profile))
    except NoAnswer as error:
        print(f"{chosen.name} at {chosen.host}:{chosen.port}: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(
            f"cannot evaluate {chosen.name} at {chosen.host}:{chosen.port}: {error}",
            file=sys.stderr,
        )
        return 2
    for line in report.lines():
        print(line)
    if config.evaluate.report is not None:
        try:
            pathlib.Path(config.evaluate.report).write_text(
                report.render(), encoding="utf-8", newline="\n"
            )
        except OSError as error:
            print(f"cannot write the report: {error}", file=sys.stderr)
            return 2
        print(f"wrote {config.evaluate.report}")
    return 1 if report.failed else 0


__all__ = ["Report", "catalog_lines", "evaluate", "evaluate_loopback", "run"]
