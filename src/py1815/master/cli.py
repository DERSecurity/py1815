"""``py1815-master``: the master's service and console from a command line.

``console`` serves the web console and the service behind it. ``serve`` runs
the service alone, a line of JSON at a time, for a test rig. Either may be
given outstations to add at startup, and ``console --demo`` also starts a
simulated IEEE 1815.2 DER in the same process and connects to it, so there is
something to look at with nothing else running. ``poll`` reads an outstation
once and prints what it answered. ``evaluate`` runs checks against an
outstation and reports a verdict for each.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.metadata
import logging
import logging.handlers
import os
import pathlib
import secrets
import signal
import sys
import time
import webbrowser
from collections.abc import Sequence
from typing import Any

from py1815.master import evaluate, poll
from py1815.master.api import DEFAULT_RECONNECT
from py1815.master.bench import DEFAULT_SETTLE
from py1815.master.capture import CaptureFile
from py1815.master.config import LOG_LEVELS, MEGABYTE, ConfigError, MasterConfig, read
from py1815.master.service import DEFAULT_HTTP_BIND, HttpServer, LineServer, Service
from py1815.profile import der, device_profile, load
from py1815.profile.model import Composition, MapError, PointMap
from py1815.server import OutstationServer

logger = logging.getLogger(__name__)

DEMO_NAME = "simulated-der"

#: Where the console's token is read from when it is not given on the command
#: line, so a container can be handed one without it appearing in its command.
TOKEN_VARIABLE = "PY1815_MASTER_TOKEN"


class Demo:
    """A simulated DER, served on this machine and added to a service."""

    def __init__(self, service: Service, point_map: PointMap, *, tick: float = 1.0) -> None:
        self._service = service
        self._tick = tick
        self.simulation = der.build(point_map)
        self._server = OutstationServer(self.simulation.outstation.session(), bind="127.0.0.1:0")
        self._running: asyncio.Task[None] | None = None

    @property
    def port(self) -> int:
        return self._server.port

    async def start(self) -> None:
        await self._server.start()
        self._running = asyncio.create_task(self._advance(), name="dnp3-master-demo")
        self._service.set_profile(DEMO_NAME, self.simulation.outstation.point_map)
        # The document the simulated DER publishes, so the console can compare
        # what it serves with what it declares.
        outstation = self.simulation.outstation
        document = device_profile.build(outstation, outstation.session())
        self._service.set_device_profile(DEMO_NAME, device_profile.render(document))
        await self._service.handle(
            {
                "op": "add",
                "params": {
                    "name": DEMO_NAME,
                    "host": "127.0.0.1",
                    "port": self.port,
                    "integrity_interval": 30,
                    "event_interval": 2,
                },
            }
        )

    async def _advance(self) -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(self._tick)
            now = time.monotonic()
            self.simulation.advance(now - last)
            last = now
            self._server.notify()

    async def stop(self) -> None:
        if self._running is not None:
            self._running.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._running
        await self._server.stop()


def _outstation(text: str) -> tuple[str, str, int]:
    name, separator, where = text.partition("=")
    host, colon, port = where.rpartition(":")
    if not separator or not colon or not name or not host:
        raise argparse.ArgumentTypeError(f"{text!r} is not NAME=HOST:PORT")
    try:
        return name, host, int(port)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{port!r} is not a port") from None


def _classes(text: str) -> list[int]:
    try:
        classes = [int(number) for number in text.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not event classes, as in 1,2,3") from None
    if not classes or any(number not in (1, 2, 3) for number in classes):
        raise argparse.ArgumentTypeError(f"{text!r} is not event classes, as in 1,2,3")
    return classes


async def _keep_trying(service: Service, name: str, seconds: float) -> None:
    """Connect to an outstation that was not there yet, for as long as was allowed.

    For a master started beside its outstation, which may be the first of the
    two to be ready. The service's ``connect`` does the trying, once a second.
    """
    answer = await service.handle(
        {"op": "connect", "outstation": name, "params": {"wait": seconds}}
    )
    if answer["ok"]:
        print(f"{name}: connected", flush=True)
    else:
        print(f"{name}: still not reachable after {seconds:g} s", file=sys.stderr)


#: Where ``serve`` listens unless told otherwise.
DEFAULT_LINE_BIND = "127.0.0.1:8816"


def configuration(args: argparse.Namespace) -> MasterConfig:
    """Build the configuration from ``--config`` and the command-line flags.

    The file is the base. A flag that is given overrides the file: the
    top-level settings directly, and the per-outstation flags by changing
    ``defaults``. An outstation entry in the file that sets the same thing
    keeps its own value. Outstations named with ``--outstation`` are added to
    those in the file.

    Raises :class:`~py1815.master.config.ConfigError`.
    """
    document: dict[str, Any] = {}
    if getattr(args, "config", None):
        document = read(args.config)
        # Report a mistake in the file as the file's, before flags are applied.
        MasterConfig.from_mapping(document)
    for key in (
        "allow_control",
        "bind",
        "tables",
        "connect_wait",
        "capture",
        "capture_max_mb",
        "capture_keep",
        "log_file",
        "log_max_mb",
        "log_keep",
        "log_level",
    ):
        value = getattr(args, key, None)
        if value is not None:
            document[key] = value

    evaluating = dict(document.get("evaluate") or {})
    for key, flag in (("settle", "settle"), ("curves", "curves"), ("report", "report")):
        value = getattr(args, flag, None)
        if value is not None:
            evaluating[key] = value
    if getattr(args, "check", None):
        evaluating["checks"] = list(args.check)
    if evaluating:
        document["evaluate"] = evaluating

    defaults = dict(document.get("defaults") or {})
    for key in (
        "outstation_address",
        "master_address",
        "manual",
        "profile",
        "read_retries",
        "device_profile",
    ):
        value = getattr(args, key, None)
        if value is not None:
            defaults[key] = value
    tls = {
        name: getattr(args, f"tls_{name}")
        for name in ("ca", "certificate", "key", "server_name")
        if getattr(args, f"tls_{name}", None) is not None
    }
    if tls:
        defaults["tls"] = {**(defaults.get("tls") or {}), **tls}
    if args.reconnect is not None:
        defaults["reconnect"] = args.reconnect or None
    if args.unsolicited is not None:
        tasks = dict(defaults.get("tasks") or {})
        defaults["tasks"] = {**tasks, "enable_unsolicited": args.unsolicited}
    repeat = dict(defaults.get("repeat") or {})
    if args.integrity_interval is not None:
        repeat["integrity"] = args.integrity_interval
    if args.event_interval is not None:
        repeat["events"] = args.event_interval
    if args.output_interval is not None:
        repeat["outputs"] = args.output_interval or None
    if repeat:
        defaults["repeat"] = repeat
    if defaults:
        document["defaults"] = defaults

    named = [{"name": name, "host": host, "port": port} for name, host, port in args.outstation]
    if named:
        document["outstations"] = [*(document.get("outstations") or []), *named]
    return MasterConfig.from_mapping(document)


async def _add_outstations(
    service: Service,
    config: MasterConfig,
    point_map: PointMap | None = None,
    waiting: list[asyncio.Task[None]] | None = None,
) -> bool:
    """Add each configured outstation to the service. Return False if one is refused."""
    for outstation in config.outstations:
        name = outstation.name
        if point_map is not None and outstation.profile:
            service.set_profile(name, point_map)
        if outstation.device_profile is not None:
            try:
                document = pathlib.Path(outstation.device_profile).read_text(encoding="utf-8")
                service.set_device_profile(name, document)
            except (OSError, UnicodeDecodeError, ValueError) as error:
                print(f"{name}: {outstation.device_profile}: {error}", file=sys.stderr)
                return False
        answer = await service.handle(
            {"op": "add", "params": outstation.add_params(allow_control=config.allow_control)}
        )
        if not answer["ok"]:
            # An unreachable outstation is still added and shown as not
            # connected. Any other error means it could not be added at all.
            print(f"{name}: {answer['error']['message']}", file=sys.stderr)
            if answer["error"]["kind"] != "connection":
                return False
            if config.connect_wait > 0 and waiting is not None:
                waiting.append(
                    asyncio.create_task(_keep_trying(service, name, config.connect_wait))
                )
    return True


def _service(config: MasterConfig) -> Service | None:
    """Return the service the configuration describes.

    Return None, having said why, when the capture file cannot be created.
    """
    capture = None
    if config.capture is not None:
        try:
            capture = CaptureFile(
                config.capture,
                max_bytes=round(config.capture_max_mb * MEGABYTE),
                keep=config.capture_keep,
            )
        except OSError as error:
            print(f"cannot write the capture file: {error}", file=sys.stderr)
            return None
    return Service(allow_control=config.allow_control, capture=capture)


async def run_console(
    args: argparse.Namespace,
    point_map: PointMap | None = None,
    profile_map: PointMap | None = None,
    config: MasterConfig | None = None,
) -> int:
    """Serve the console until interrupted or told to stop.

    ``point_map`` is the map a simulated DER is built from, for the
    demonstration. ``profile_map`` is the profile the outstations named on
    the command line are meant to serve. ``config`` is built from ``args``
    when not given.
    """
    if config is None:
        config = configuration(args)
    service = _service(config)
    if service is None:
        return 2
    token = args.token or os.environ.get(TOKEN_VARIABLE) or None
    if token is None and args.new_token:
        token = secrets.token_urlsafe(16)
    waiting: list[asyncio.Task[None]] = []
    try:
        server = HttpServer(
            service,
            bind=config.bind or DEFAULT_HTTP_BIND,
            token=token,
            without_token=args.no_token,
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        await service.close()
        return 2
    demo = Demo(service, point_map, tick=args.tick) if point_map is not None else None
    profile = point_map if point_map is not None else profile_map
    await server.start()
    try:
        if demo is not None:
            await demo.start()
        if not await _add_outstations(service, config, profile, waiting):
            return 2
        print(f"Satori DNP3 master console at {server.url}", flush=True)
        if config.allow_control:
            print("  commanding is on: this console can operate outputs", flush=True)
        if config.capture is not None:
            print(f"  writing every frame to {config.capture}", flush=True)
        if demo is not None:
            print(
                f"  a simulated DER is listening on 127.0.0.1:{demo.port} "
                f"and has been added as {DEMO_NAME}",
                flush=True,
            )
        if args.open:
            webbrowser.open(server.url)
        await service.stopped.wait()
    finally:
        for task in waiting:
            task.cancel()
        if demo is not None:
            await demo.stop()
        await server.stop()
        await service.close()
    return 0


async def run_service(
    args: argparse.Namespace,
    profile_map: PointMap | None = None,
    config: MasterConfig | None = None,
) -> int:
    """Serve the line service until interrupted or told to stop."""
    if config is None:
        config = configuration(args)
    bind = config.bind or DEFAULT_LINE_BIND
    service = _service(config)
    if service is None:
        return 2
    waiting: list[asyncio.Task[None]] = []
    try:
        server = LineServer(service, bind=bind)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        await service.close()
        return 2
    await server.start()
    try:
        if not await _add_outstations(service, config, profile_map, waiting):
            return 2
        print(
            f"DNP3 master service listening on {bind.rpartition(':')[0]}:{server.port}",
            flush=True,
        )
        if config.capture is not None:
            print(f"  writing every frame to {config.capture}", flush=True)
        await service.stopped.wait()
    finally:
        for task in waiting:
            task.cancel()
        await server.stop()
        await service.close()
    return 0


def _add_outstation_options(parser: argparse.ArgumentParser) -> None:
    """Add the options shared by every command.

    Each one defaults to None, meaning "not given", so that a flag overrides
    the configuration file only when it is actually used.
    """
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="a JSON configuration file; flags given on the command line override it "
        "(print a complete one with `py1815-master config`)",
    )
    parser.add_argument(
        "--allow-control",
        action="store_true",
        default=None,
        help="allow operations and tasks that write to an outstation: outputs, counters, "
        "clock and restart indication (default: read only)",
    )
    parser.add_argument(
        "--capture",
        default=None,
        metavar="FILE",
        help="write every frame sent and received to this pcap file as it crosses the "
        "wire (default: no file)",
    )
    parser.add_argument(
        "--capture-max-mb",
        type=float,
        default=None,
        metavar="MB",
        help="start a new capture file once the current one reaches this size (default: 100)",
    )
    parser.add_argument(
        "--capture-keep",
        type=int,
        default=None,
        metavar="FILES",
        help="older capture files to keep after rotation (default: 10)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        metavar="FILE",
        help="also write the log to this file, rotated by size (default: terminal only)",
    )
    parser.add_argument(
        "--log-max-mb",
        type=float,
        default=None,
        metavar="MB",
        help="start a new log file once the current one reaches this size (default: 10)",
    )
    parser.add_argument(
        "--log-keep",
        type=int,
        default=None,
        metavar="FILES",
        help="older log files to keep after rotation (default: 5)",
    )
    parser.add_argument(
        "--log-level",
        choices=LOG_LEVELS,
        default=None,
        help="the lowest level written to the log file (default: info)",
    )
    parser.add_argument(
        "--outstation",
        action="append",
        default=[],
        type=_outstation,
        metavar="NAME=HOST:PORT",
        help="an outstation to add and connect to at startup; repeat for more than one",
    )
    parser.add_argument(
        "--profile",
        action="store_true",
        default=None,
        help="the outstations are IEEE 1815.2 DER: name their points from the profile "
        "tables and show the profile points they have not reported",
    )
    parser.add_argument(
        "--device-profile",
        default=None,
        metavar="FILE",
        help="a DNP3 Device Profile document for the outstations, to compare what they "
        "serve with (default: none)",
    )
    parser.add_argument(
        "--tables",
        default=None,
        help=f"the profile tables file, for --profile and --demo (default: "
        f"${load.TABLES_VARIABLE}, else ~/.py1815/{load.TABLES_NAME})",
    )
    parser.add_argument(
        "--connect-wait",
        type=float,
        default=None,
        metavar="SECONDS",
        help="keep trying for this long to reach an outstation that is not there at "
        "startup (default: try once)",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        default=None,
        help="send only what is asked for: no startup sequence, no event poll, no "
        "confirmation (default: run the automatic tasks)",
    )
    parser.add_argument(
        "--unsolicited",
        type=_classes,
        default=None,
        metavar="CLASSES",
        help="enable unsolicited reporting for these event classes after startup, as in "
        "1,2,3 (default: do not)",
    )
    parser.add_argument(
        "--reconnect",
        type=float,
        default=None,
        metavar="SECONDS",
        help="seconds between reconnection attempts after a lost connection "
        f"(default: {DEFAULT_RECONNECT:g}; 0 for never)",
    )
    parser.add_argument(
        "--outstation-address", type=int, default=None, help="link address (default: 1024)"
    )
    parser.add_argument(
        "--master-address", type=int, default=None, help="link address (default: 1)"
    )
    parser.add_argument(
        "--read-retries",
        type=poll.count,
        default=None,
        metavar="N",
        help="send a read that times out again this many times; nothing else is ever "
        "sent again (default: 0)",
    )
    poll.add_tls_options(parser)
    parser.add_argument(
        "--integrity-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="repeat an integrity poll this often (default: do not)",
    )
    parser.add_argument(
        "--output-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="repeat a read of output status this often (default: as often as the "
        "integrity poll, which does not include it; 0 for never)",
    )
    parser.add_argument(
        "--event-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="repeat an event poll this often (default: do not)",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="py1815-master", description="A DNP3 master for exercising outstations."
    )
    parser.add_argument("--verbose", action="store_true", help="log what the master does")
    commands = parser.add_subparsers(dest="command", required=True)

    console = commands.add_parser("console", help="serve the web console")
    console.add_argument(
        "--bind",
        default=None,
        help=f"where the console listens (default: {DEFAULT_HTTP_BIND}, this machine only)",
    )
    console.add_argument(
        "--token",
        default=None,
        help="required of every request to the service; needed to listen on anything but "
        f"this machine (default: ${TOKEN_VARIABLE})",
    )
    console.add_argument(
        "--new-token",
        action="store_true",
        help="when no token is given, make one for this run and print the address that carries it",
    )
    console.add_argument(
        "--no-token",
        action="store_true",
        help="listen beyond this machine with no token. For a container whose port is "
        "published to this machine only: anyone who can reach the port can use the console",
    )
    console.add_argument("--open", action="store_true", help="open the console in a browser")
    console.add_argument(
        "--demo",
        action="store_true",
        help="also start a simulated IEEE 1815.2 DER and connect to it",
    )
    console.add_argument(
        "--tick", type=float, default=1.0, help="seconds between steps of the simulated DER"
    )
    _add_outstation_options(console)

    serve = commands.add_parser("serve", help="serve the JSON line service, for a test rig")
    serve.add_argument(
        "--bind",
        default=None,
        help=f"where the service listens, on this machine (default: {DEFAULT_LINE_BIND})",
    )
    _add_outstation_options(serve)

    config = commands.add_parser(
        "config",
        help="print the complete configuration as JSON, for editing and for --config",
    )
    config.add_argument("--bind", default=None, help="where the console or service listens")
    config.add_argument(
        "--out", type=pathlib.Path, default=None, help="write to this file instead of stdout"
    )
    _add_outstation_options(config)

    evaluating = commands.add_parser(
        "evaluate",
        help="run checks against an outstation and report a verdict for each",
        description="Run checks against one outstation. Checks that write to it run only "
        "with --allow-control: they change its settings, enable and disable its functions, "
        "and stop and start it. Exit status: 0 when no check failed, 1 when one did, 2 when "
        "the run could not be made.",
    )
    evaluating.add_argument(
        "name",
        nargs="?",
        default=None,
        help="the outstation to evaluate, when more than one is configured",
    )
    evaluating.add_argument(
        "--list", action="store_true", help="print the checks and exit; nothing is sent"
    )
    evaluating.add_argument(
        "--check",
        action="append",
        default=None,
        metavar="NAME",
        help="run only this check or set of checks, by a name --list prints; may be "
        "repeated (default: all)",
    )
    evaluating.add_argument(
        "--settle",
        type=float,
        default=None,
        metavar="SECONDS",
        help="how long to wait for the outstation to reach a state it was commanded to "
        f"(default: {DEFAULT_SETTLE:g})",
    )
    evaluating.add_argument(
        "--curves",
        type=int,
        default=None,
        metavar="N",
        help="how many curves the outstation stores (default: found by selecting each)",
    )
    evaluating.add_argument(
        "--report",
        default=None,
        metavar="FILE",
        help="also write the report to this file as JSON (default: no file)",
    )
    _add_outstation_options(evaluating)

    polling = commands.add_parser(
        "poll", help="run one integrity poll against an outstation and print what it answered"
    )
    poll.add_options(polling, default_port=20000)
    polling.add_argument(
        "--outstation-address", type=int, default=1024, help="link address (default: 1024)"
    )
    polling.add_argument("--master-address", type=int, default=1, help="link address (default: 1)")
    return parser


def _interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


#: How each log record is written, to the terminal and to the file.
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def configure_logging(config: MasterConfig, *, verbose: bool) -> logging.Handler | None:
    """Set up the root logger: the terminal, and the rotating log file if configured.

    The terminal shows warnings, or everything from INFO with ``verbose``.
    The file gets ``log_level`` and above. Return the file's handler, or None
    when there is no file. Raises ``OSError`` if the file cannot be opened.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    terminal = logging.StreamHandler()
    terminal.setLevel(logging.INFO if verbose else logging.WARNING)
    terminal.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(terminal)
    levels = [terminal.level]
    file_handler: logging.Handler | None = None
    if config.log_file is not None:
        file_handler = logging.handlers.RotatingFileHandler(
            config.log_file,
            maxBytes=round(config.log_max_mb * MEGABYTE),
            backupCount=config.log_keep,
            encoding="utf-8",
        )
        file_handler.setLevel(config.log_level.upper())
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(file_handler)
        levels.append(file_handler.level)
    root.setLevel(min(levels))
    return file_handler


def _version() -> str:
    try:
        return importlib.metadata.version("py1815")
    except importlib.metadata.PackageNotFoundError:
        return "(not installed)"


def _log_start(config: MasterConfig, command: str) -> None:
    """Write what the master was started with, so a log file says what it covers."""
    logger.info(
        "dnp3 master: py1815 %s started (%s), commanding %s, capture %s",
        _version(),
        command,
        "on" if config.allow_control else "off",
        config.capture or "none",
    )
    for outstation in config.outstations:
        logger.info(
            "dnp3 master: outstation %s at %s:%d, link %d to %d",
            outstation.name,
            outstation.host,
            outstation.port,
            outstation.master_address,
            outstation.outstation_address,
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "poll":
        # A one-shot client: no configuration file and no log file.
        logging.basicConfig(
            level=logging.INFO if args.verbose else logging.WARNING, format=LOG_FORMAT
        )
        return poll.run(args)
    try:
        config = configuration(args)
    except ConfigError as error:
        print(str(error), file=sys.stderr)
        return 2
    if args.command != "config":
        try:
            log_file = configure_logging(config, verbose=args.verbose)
        except OSError as error:
            print(f"cannot write the log file: {error}", file=sys.stderr)
            return 2
        if log_file is not None:
            print(f"  logging to {config.log_file}", flush=True)
        _log_start(config, args.command)
    if args.command == "config":
        if args.out is None:
            sys.stdout.write(config.render())
        else:
            args.out.write_text(config.render(), encoding="utf-8", newline="\n")
            print(f"wrote {args.out}")
        return 0
    if args.command == "evaluate":
        return evaluate.run(args, config)

    point_map: PointMap | None = None
    demo = args.command == "console" and args.demo
    profiled = config.defaults.profile or any(each.profile for each in config.outstations)
    if demo or profiled:
        try:
            point_map = load.load(config.tables, Composition())
        except (MapError, ValueError, OSError) as error:
            print(str(error), file=sys.stderr)
            return 1
    profile_map = point_map if profiled else None
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        if args.command == "console":
            return asyncio.run(run_console(args, point_map if demo else None, profile_map, config))
        return asyncio.run(run_service(args, profile_map, config))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
