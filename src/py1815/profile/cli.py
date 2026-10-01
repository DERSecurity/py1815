"""``py1815-der``: fetch the profile tables, run a DER outstation, and poll one.

    py1815-der tables fetch      download the IEEE point tables and read them
    py1815-der run               serve a simulated DER as an IEEE 1815.2 outstation
    py1815-der poll              ask a running outstation for everything, once

The tables are IEEE's and are not part of this package (D36). ``tables fetch``
downloads them from IEEE to the machine it runs on and reads them into the
form the outstation loads; ``tables build`` does the reading for a workbook
already downloaded.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import logging
import pathlib
import signal
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Sequence

from py1815.profile import der, extract, load, probe
from py1815.profile.model import Composition, Kind, MapError, PointMap
from py1815.server import DEFAULT_PORT, OutstationServer

logger = logging.getLogger("py1815.profile")

#: The most octets a download may run to. The archive is under a megabyte; a
#: response a hundred times that is not the archive.
_MAX_DOWNLOAD = 100 * 1024 * 1024

_TERMS = (
    "The Profile Companion Data Point Tables are IEEE's. This copy is for use on "
    "this machine: IEEE's terms do not permit redistributing the workbook or the "
    "file read from it, so keep both out of anything you publish."
)

_GROUP_NAMES = {1: "binary inputs", 20: "counters", 21: "frozen counters", 30: "analog inputs"}


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "py1815"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data: bytes = response.read(_MAX_DOWNLOAD + 1)
    if len(data) > _MAX_DOWNLOAD:
        raise OSError(f"the download exceeds {_MAX_DOWNLOAD} octets")
    return data


def _workbook_from_archive(data: bytes) -> tuple[str, bytes]:
    """The tables workbook inside IEEE's download, by name and content."""
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = [name for name in archive.namelist() if name.lower().endswith(".xlsx")]
        tables = [name for name in names if "point tables" in name.lower()] or names
        if len(tables) != 1:
            raise OSError(f"expected one workbook in the download and found {len(names)}")
        return pathlib.PurePosixPath(tables[0]).name, archive.read(tables[0])


def _write_tables(workbook: pathlib.Path, out: pathlib.Path) -> int:
    try:
        document = extract.extract(workbook)
    except extract.ExtractionError as error:
        print(f"could not read {workbook}: {error}", file=sys.stderr)
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(extract.serialize(document), encoding="utf-8")
    print(f"wrote {out}")
    print(f"  {extract.summary(document)}")
    print(_TERMS)
    return 0


def _tables_fetch(args: argparse.Namespace) -> int:
    out: pathlib.Path = args.out or load.default_tables()
    print(f"downloading {args.url}")
    try:
        name, content = _workbook_from_archive(_download(args.url))
    except (OSError, urllib.error.URLError, zipfile.BadZipFile) as error:
        print(
            f"download failed: {error}\n"
            f"Download the archive from {args.url} yourself, unpack it, and run:\n"
            "  py1815-der tables build <the workbook>.xlsx",
            file=sys.stderr,
        )
        return 1
    out.parent.mkdir(parents=True, exist_ok=True)
    workbook = out.parent / name
    workbook.write_bytes(content)
    print(f"saved {workbook}")
    return _write_tables(workbook, out)


def _tables_build(args: argparse.Namespace) -> int:
    if not args.workbook.is_file():
        print(f"no such file: {args.workbook}", file=sys.stderr)
        return 2
    return _write_tables(args.workbook, args.out or load.default_tables())


def _composition(args: argparse.Namespace) -> Composition:
    return Composition(
        meters=args.meters,
        der_units=args.der_units,
        inverters=args.inverters,
        batteries=args.batteries,
    )


def _load(args: argparse.Namespace) -> PointMap | None:
    try:
        return load.load(args.tables, _composition(args))
    except MapError as error:
        print(str(error), file=sys.stderr)
        return None


def _points(args: argparse.Namespace) -> int:
    point_map = _load(args)
    if point_map is None:
        return 1
    outstation = der.build(point_map, seed=args.seed).outstation
    for kind in Kind:
        for point in outstation.served(kind):
            marker = "M" if point.mandatory else " "
            print(f"{kind.value}{point.index:<6} {marker} {point.name}")
    return 0


async def _serve(args: argparse.Namespace, point_map: PointMap) -> None:
    simulation = der.build(point_map, seed=args.seed)
    outstation = simulation.outstation
    session = outstation.session(
        outstation_address=args.outstation_address, master_address=args.master_address
    )
    server = OutstationServer(session, bind=args.bind)
    await server.start()
    served = ", ".join(f"{len(outstation.served(kind))} {kind.value}" for kind in Kind)
    print(
        f"IEEE 1815.2 DER outstation (profile version {point_map.profile_version}) "
        f"listening on {args.bind}\n"
        f"  link address {args.outstation_address}, master {args.master_address}; "
        f"serving {served}",
        flush=True,
    )
    try:
        last = time.monotonic()
        while True:
            await asyncio.sleep(args.tick)
            now = time.monotonic()
            simulation.advance(now - last)
            last = now
    finally:
        await server.stop()


def _interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _run(args: argparse.Namespace) -> int:
    point_map = _load(args)
    if point_map is None:
        return 1
    # A container's first process ignores a termination signal it has no
    # handler for, and `docker stop` would then wait out its grace period
    # before killing it. Handled, it stops the listener the way Ctrl-C does.
    with contextlib.suppress(ValueError, AttributeError):
        signal.signal(signal.SIGTERM, _interrupt)
    try:
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(_serve(args, point_map))
    except OSError as error:
        print(f"cannot listen on {args.bind}: {error}", file=sys.stderr)
        return 1
    return 0


def _poll(args: argparse.Namespace) -> int:
    try:
        result = asyncio.run(
            probe.integrity_poll(
                args.host,
                args.port,
                outstation=args.outstation_address,
                master=args.master_address,
                timeout=args.timeout,
            )
        )
    except probe.ProbeError as error:
        print(str(error), file=sys.stderr)
        return 1

    counts = ", ".join(f"{len(result.group(group))} {name}" for group, name in _GROUP_NAMES.items())
    print(f"{args.host}:{args.port} answered in {result.fragments} fragment(s): {counts}")
    print(
        f"  {len(result.events)} event(s); indications 0x{result.indications[0]:02X} "
        f"0x{result.indications[1]:02X}"
    )

    # Names and units come from the tables when this machine has them; the
    # poll itself needs none, so their absence only shortens the report.
    try:
        point_map: PointMap | None = load.load(args.tables)
    except MapError:
        point_map = None

    def live_first(value: probe.Value) -> tuple[bool, int]:
        # The meter ahead of the nameplate: what moves is what shows the
        # outstation is alive, and an enumeration says little as a number.
        point = point_map.get(Kind.AI, value.index) if point_map else None
        measured = (
            point is not None
            and "meter" in (point.section or "").lower()
            and point.units not in (None, "Enum")
        )
        return (not measured, value.index)

    analogs = result.group(30)
    chosen = analogs if args.all else sorted(analogs, key=live_first)[: args.limit]
    for value in sorted(chosen, key=lambda v: v.index):
        point = point_map.get(Kind.AI, value.index) if point_map else None
        if point is None:
            print(f"  AI{value.index:<6} {value.value:>14.6g}")
            continue
        units = "" if point.units in (None, "None", "n/a") else f" {point.units}"
        reading = point.from_wire(value.value)
        print(f"  AI{value.index:<6} {reading:>14.6g}{units}  {point.name[:60]}")
    return 0


def _add_map_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tables",
        type=pathlib.Path,
        default=None,
        help=f"the profile tables file (default: ${load.TABLES_VARIABLE}, else "
        f"~/.py1815/{load.TABLES_NAME})",
    )
    for name, what in (
        ("meters", "meters"),
        ("der-units", "DER units"),
        ("inverters", "inverters"),
        ("batteries", "batteries"),
    ):
        parser.add_argument(
            f"--{name}", type=int, default=0, help=f"equipment blocks to resolve for {what}"
        )
    parser.add_argument("--seed", type=int, default=0, help="seed for the simulation's noise")


def _add_link_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="py1815-der", description="An IEEE 1815.2 DER outstation over DNP3."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log each request handled")
    commands = parser.add_subparsers(dest="command", required=True)

    tables = commands.add_parser("tables", help="obtain the IEEE 1815.2 point tables")
    actions = tables.add_subparsers(dest="action", required=True)
    fetch = actions.add_parser("fetch", help="download the tables from IEEE and read them")
    fetch.add_argument("--url", default=extract.SOURCE_URL)
    fetch.add_argument("--out", type=pathlib.Path, default=None, help="where to write the file")
    fetch.set_defaults(handler=_tables_fetch)
    build = actions.add_parser("build", help="read a workbook already downloaded")
    build.add_argument("workbook", type=pathlib.Path)
    build.add_argument("--out", type=pathlib.Path, default=None, help="where to write the file")
    build.set_defaults(handler=_tables_build)

    run = commands.add_parser("run", help="serve a simulated DER")
    _add_map_options(run)
    _add_link_options(run)
    run.add_argument(
        "--bind",
        default=f"127.0.0.1:{DEFAULT_PORT}",
        help="host:port to listen on (default: loopback only)",
    )
    run.add_argument("--tick", type=float, default=1.0, help="seconds between simulation steps")
    run.set_defaults(handler=_run)

    points = commands.add_parser("points", help="list the points the simulated DER serves")
    _add_map_options(points)
    points.set_defaults(handler=_points)

    poll = commands.add_parser("poll", help="run one integrity poll against an outstation")
    poll.add_argument("--host", default="127.0.0.1")
    poll.add_argument("--port", type=int, default=DEFAULT_PORT)
    poll.add_argument("--timeout", type=float, default=5.0)
    poll.add_argument("--tables", type=pathlib.Path, default=None, help="for point names")
    poll.add_argument("--all", action="store_true", help="print every analog input")
    poll.add_argument("--limit", type=int, default=12, help="analog inputs to print")
    _add_link_options(poll)
    poll.set_defaults(handler=_poll)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line, returning the process exit status."""
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(name)s %(message)s",
    )
    handler = args.handler
    return int(handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
