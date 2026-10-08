"""``py1815-der``: fetch the profile tables, run a DER outstation, and poll one.

    py1815-der tables fetch      download the IEEE point tables and read them
    py1815-der run               serve a simulated DER as an IEEE 1815.2 outstation
    py1815-der poll              ask a running outstation for everything, once
    py1815-der profile           write the outstation's DNP3 Device Profile document
    py1815-der config            print the complete configuration as JSON, for editing

``run``, ``points`` and ``profile`` take their settings from ``--config FILE``,
from flags, or both. A flag overrides the file. See :mod:`py1815.profile.config`.

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
import math
import pathlib
import signal
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Sequence
from typing import Any

from py1815.control import CommandStatus
from py1815.profile import der, device_profile, extract, load, probe
from py1815.profile.config import DerConfig
from py1815.profile.model import Kind, MapError, PointMap
from py1815.server import DEFAULT_PORT, OutstationServer
from py1815.settings import ConfigError, read

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
        # The cap on the download bounds the archive, not what it inflates to:
        # a small archive can hold a member of any size. The declared size is
        # the bound that matters, because the reader stops at it: a member
        # that inflates past its declaration fails its checksum instead.
        if archive.getinfo(tables[0]).file_size > _MAX_DOWNLOAD:
            raise OSError(f"the workbook in the download exceeds {_MAX_DOWNLOAD} octets")
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


#: Flags that set a top-level setting of the same name.
_TOP_LEVEL_FLAGS = (
    "bind",
    "outstation_address",
    "master_address",
    "unsolicited",
    "read_only",
    "level2",
    "event_capacity",
    "max_response",
    "select_timeout",
    "idle_timeout",
)
_COMPOSITION_FLAGS = ("meters", "der_units", "inverters", "batteries")
_IDENTITY_FLAGS = ("vendor", "device", "hardware_version", "software_version", "author")


def configuration(args: argparse.Namespace) -> DerConfig:
    """Build the configuration from ``--config`` and the command-line flags.

    The file is the base, and a flag that is given overrides it. A command
    that does not have a flag leaves that setting as the file has it.

    Raises :class:`~py1815.settings.ConfigError`.
    """
    document: dict[str, Any] = {}
    if getattr(args, "config", None):
        document = read(args.config)
        # Report a mistake in the file as the file's, before flags are applied.
        DerConfig.from_mapping(document)

    def given(name: str) -> Any:
        return getattr(args, name, None)

    for name in _TOP_LEVEL_FLAGS:
        if given(name) is not None:
            document[name] = given(name)
    if given("tables") is not None:
        document["tables"] = str(given("tables"))
    if given("any_master"):
        document["master_address"] = None
    for section, names in (("composition", _COMPOSITION_FLAGS), ("identity", _IDENTITY_FLAGS)):
        chosen = {name: given(name) for name in names if given(name) is not None}
        if chosen:
            document[section] = {**(document.get(section) or {}), **chosen}
    simulation = {name: given(name) for name in ("seed", "tick") if given(name) is not None}
    if simulation:
        document["simulation"] = {**(document.get("simulation") or {}), **simulation}
    return DerConfig.from_mapping(document)


def _configured(args: argparse.Namespace) -> DerConfig | None:
    """Return the configuration, or None after printing why it cannot be used."""
    try:
        return configuration(args)
    except ConfigError as error:
        print(str(error), file=sys.stderr)
        return None


def _load_map(config: DerConfig) -> PointMap | None:
    """Load the point map for the configured composition, or print why not."""
    try:
        return load.load(config.tables, config.composition)
    except (MapError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return None


def _load(args: argparse.Namespace) -> PointMap | None:
    config = _configured(args)
    return None if config is None else _load_map(config)


def _build(config: DerConfig, point_map: PointMap) -> der.Simulation | None:
    """Build the simulated DER, or print why the configuration does not fit it."""
    try:
        return der.build(point_map, seed=config.seed, **config.outstation_options())
    except (MapError, ValueError) as error:
        # For example an event policy that names a point this DER does not serve.
        print(str(error), file=sys.stderr)
        return None


def _config(args: argparse.Namespace) -> int:
    config = _configured(args)
    if config is None:
        return 2
    if args.out is None:
        sys.stdout.write(config.render())
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(config.render(), encoding="utf-8", newline="\n")
        print(f"wrote {args.out}")
    return 0


def _points(args: argparse.Namespace) -> int:
    config = _configured(args)
    if config is None:
        return 2
    point_map = _load_map(config)
    if point_map is None:
        return 1
    simulation = _build(config, point_map)
    if simulation is None:
        return 2
    outstation = simulation.outstation
    if args.coverage:
        print(outstation.coverage().render())
        return 0
    for kind in Kind:
        for point in outstation.served(kind):
            marker = "M" if point.mandatory else " "
            print(f"{kind.value}{point.index:<6} {marker} {point.name}")
    return 0


async def _serve(config: DerConfig, simulation: der.Simulation) -> None:
    outstation = simulation.outstation
    point_map = outstation.point_map
    session = outstation.session(**config.session_options())
    server = OutstationServer(session, bind=config.bind, idle_timeout=config.idle_timeout)
    await server.start()
    served = ", ".join(f"{len(outstation.served(kind))} {kind.value}" for kind in Kind)
    master = "any" if config.master_address is None else config.master_address
    print(
        f"IEEE 1815.2 DER outstation (profile version {point_map.profile_version}) "
        f"listening on {config.bind}\n"
        f"  link address {config.outstation_address}, master {master}; "
        f"serving {served}",
        flush=True,
    )
    try:
        last = time.monotonic()
        while True:
            await asyncio.sleep(config.tick)
            now = time.monotonic()
            simulation.advance(now - last)
            last = now
            # Report the events this step buffered now, if a master has
            # enabled their class, instead of at the listener's next check.
            server.notify()
    finally:
        await server.stop()


def _interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _run(args: argparse.Namespace) -> int:
    config = _configured(args)
    if config is None:
        return 2
    point_map = _load_map(config)
    if point_map is None:
        return 1
    simulation = _build(config, point_map)
    if simulation is None:
        return 2
    # A container's first process ignores a termination signal it has no
    # handler for, and `docker stop` would then wait out its grace period
    # before killing it. Handled, it stops the listener the way Ctrl-C does.
    with contextlib.suppress(ValueError, AttributeError):
        signal.signal(signal.SIGTERM, _interrupt)
    try:
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(_serve(config, simulation))
    except OSError as error:
        print(f"cannot listen on {config.bind}: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        # A setting the session refuses, such as a response size too small
        # for one block of points.
        print(str(error), file=sys.stderr)
        return 2
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


def _validate(document: str, schema: pathlib.Path) -> int:
    """Check a generated profile against the caller's copy of the schema."""
    try:
        import xmlschema  # pylint: disable=import-outside-toplevel
    except ModuleNotFoundError:
        print("validating needs the xmlschema package: pip install xmlschema", file=sys.stderr)
        return 2
    if not schema.is_file():
        print(f"no such schema: {schema}", file=sys.stderr)
        return 2
    errors = list(xmlschema.XMLSchema(str(schema)).iter_errors(document))
    for error in errors[:20]:
        print(f"{error.path}: {error.reason}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} error(s) against {schema.name}", file=sys.stderr)
        return 1
    print(f"valid against {schema.name}", file=sys.stderr)
    return 0


def _profile(args: argparse.Namespace) -> int:
    config = _configured(args)
    if config is None:
        return 2
    point_map = _load_map(config)
    if point_map is None:
        return 1
    simulation = _build(config, point_map)
    if simulation is None:
        return 2
    outstation = simulation.outstation
    try:
        session = outstation.session(**config.session_options())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    host, _, port = config.bind.rpartition(":")
    described = config.identity
    identity = device_profile.Identity(
        vendor=described.vendor,
        device=described.device,
        hardware_version=described.hardware_version,
        software_version=described.software_version,
        author=described.author,
        host=host or None,
        port=int(port) if port.isdigit() else None,
    )
    # The simulated DER's bindings refuse while locked out, without permission
    # to start or to stop, and for a unit it does not count in.
    statuses = (CommandStatus.BLOCKED, CommandStatus.NOT_SUPPORTED, CommandStatus.OUT_OF_RANGE)
    document = device_profile.render(
        device_profile.build(outstation, session, identity, statuses=statuses)
    )
    if args.out is None:
        sys.stdout.write(document)
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(document, encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    return _validate(document, args.validate) if args.validate is not None else 0


def _count(text: str) -> int:
    """An equipment count from the command line: a whole number, not below zero."""
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if number < 0:
        raise argparse.ArgumentTypeError(f"{number} is below zero; a count cannot be negative")
    return number


def _interval(text: str) -> float:
    """A positive, finite number of seconds.

    Zero or less would have the run loop sleep for no time at all and spin a
    processor; not-a-number and infinity are no interval either.
    """
    try:
        seconds = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number of seconds") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(f"{text} is not a positive number of seconds")
    return seconds


def _add_map_options(parser: argparse.ArgumentParser) -> None:
    """Add ``--config`` and the options that choose the point map.

    Each option defaults to None, meaning "not given", so that a flag
    overrides the configuration file only when it is actually used.
    """
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="a JSON configuration file; flags given on the command line override it "
        "(print a complete one with `py1815-der config`)",
    )
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
            f"--{name}",
            type=_count,
            default=None,
            help=f"number of {what} the DER has (default: 0)",
        )
    parser.add_argument(
        "--seed", type=int, default=None, help="seed for the simulation's noise (default: 0)"
    )


def _add_link_options(parser: argparse.ArgumentParser, *, configured: bool = True) -> None:
    """Add the link address options.

    With ``configured`` the defaults come from the configuration. Without it,
    for a command that has no configuration, they are 1024 and 1.
    """
    parser.add_argument(
        "--outstation-address",
        type=int,
        default=None if configured else 1024,
        help="the outstation's link address (default: 1024)",
    )
    parser.add_argument(
        "--master-address",
        type=int,
        default=None if configured else 1,
        help="the master's link address (default: 1)",
    )


def _add_outstation_options(parser: argparse.ArgumentParser) -> None:
    """Add the options that describe how the outstation is served."""
    _add_link_options(parser)
    parser.add_argument(
        "--any-master",
        action="store_true",
        default=None,
        help="serve whichever master address speaks first on a connection, "
        "instead of --master-address; with no transport security, any peer "
        "that can reach the listener can then read and command",
    )
    parser.add_argument(
        "--bind",
        default=None,
        help=f"host:port to listen on (default: 127.0.0.1:{DEFAULT_PORT}, this machine only)",
    )
    parser.add_argument(
        "--unsolicited",
        action="store_true",
        default=None,
        help="send unsolicited responses: announce a restart, and report the events "
        "of each class the master enables (default: report only when polled)",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="refuse every control, so a master can read and cannot command",
    )
    parser.add_argument(
        "--level2",
        action="store_true",
        default=None,
        help="answer as a DNP3 Subset Level 2 outstation, without the profile's additions",
    )
    parser.add_argument(
        "--event-capacity",
        type=int,
        default=None,
        metavar="EVENTS",
        help="events each class holds before the oldest is dropped (default: 2000)",
    )
    parser.add_argument(
        "--max-response",
        type=int,
        default=None,
        metavar="OCTETS",
        help="largest response fragment to send (default: 2048)",
    )
    parser.add_argument(
        "--select-timeout",
        type=_interval,
        default=None,
        metavar="SECONDS",
        help="how long a select stays valid (default: 10)",
    )
    parser.add_argument(
        "--idle-timeout",
        type=_interval,
        default=None,
        metavar="SECONDS",
        help="seconds of silence before a connection is closed (default: 300)",
    )


def _add_identity_options(parser: argparse.ArgumentParser) -> None:
    """Add the options that fill in the Device Profile document's identity."""
    parser.add_argument("--vendor", default=None, help="default: Not stated")
    parser.add_argument("--device", default=None, help="the device's name")
    parser.add_argument("--hardware-version", default=None)
    parser.add_argument("--software-version", default=None, help="default: this library's version")
    parser.add_argument("--author", default=None, help="default: py1815")


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
    _add_outstation_options(run)
    run.add_argument(
        "--tick",
        type=_interval,
        default=None,
        help="seconds between simulation steps (default: 1)",
    )
    run.set_defaults(handler=_run)

    points = commands.add_parser("points", help="list the points the simulated DER serves")
    _add_map_options(points)
    points.add_argument(
        "--coverage",
        action="store_true",
        help="report every point of the profile: bound, served without a binding, or absent",
    )
    points.set_defaults(handler=_points)

    profile = commands.add_parser(
        "profile", help="write the DNP3 Device Profile document for the simulated DER"
    )
    _add_map_options(profile)
    _add_outstation_options(profile)
    _add_identity_options(profile)
    profile.add_argument("--out", type=pathlib.Path, default=None, help="write here, not to stdout")
    profile.add_argument(
        "--validate",
        type=pathlib.Path,
        default=None,
        metavar="XSD",
        help=f"check the result against your copy of {device_profile.SCHEMA_FILE}",
    )
    profile.set_defaults(handler=_profile)

    config = commands.add_parser(
        "config", help="print the complete configuration as JSON, for editing and for --config"
    )
    _add_map_options(config)
    _add_outstation_options(config)
    _add_identity_options(config)
    config.add_argument("--tick", type=_interval, default=None, help="seconds between steps")
    config.add_argument(
        "--out", type=pathlib.Path, default=None, help="write to this file instead of stdout"
    )
    config.set_defaults(handler=_config)

    poll = commands.add_parser("poll", help="run one integrity poll against an outstation")
    poll.add_argument("--host", default="127.0.0.1")
    poll.add_argument("--port", type=int, default=DEFAULT_PORT)
    poll.add_argument("--timeout", type=float, default=5.0)
    poll.add_argument("--tables", type=pathlib.Path, default=None, help="for point names")
    poll.add_argument("--all", action="store_true", help="print every analog input")
    poll.add_argument("--limit", type=int, default=12, help="analog inputs to print")
    _add_link_options(poll, configured=False)
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
