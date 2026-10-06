"""``py1815-master``: the master's service and console from a command line.

``console`` serves the web console and the service behind it. ``serve`` runs
the service alone, a line of JSON at a time, for a test rig. Either may be
given outstations to add at startup, and ``console --demo`` also starts a
simulated IEEE 1815.2 DER in the same process and connects to it, so there is
something to look at with nothing else running.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import sys
import time
import webbrowser
from collections.abc import Sequence

from py1815.decode import PointType
from py1815.master.service import DEFAULT_HTTP_BIND, HttpServer, LineServer, Service
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind, MapError, PointMap
from py1815.server import OutstationServer

DEMO_NAME = "simulated-der"

_KINDS = {
    Kind.BI: (PointType.BINARY_INPUT,),
    Kind.BO: (PointType.BINARY_OUTPUT,),
    Kind.AI: (PointType.ANALOG_INPUT,),
    Kind.AO: (PointType.ANALOG_OUTPUT,),
    # A frozen counter is the counter of the same index, as it stood at a freeze.
    Kind.CTR: (PointType.COUNTER, PointType.FROZEN_COUNTER),
}


def point_names(simulation: der.Simulation) -> dict[PointType, dict[int, str]]:
    """The names the profile gives the points a simulated DER serves."""
    names: dict[PointType, dict[int, str]] = {point: {} for point in PointType}
    for kind, points in _KINDS.items():
        for served in simulation.outstation.served(kind):
            for point in points:
                names[point][served.index] = served.name
    return names


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
        self._service.set_names(DEMO_NAME, point_names(self.simulation))
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


async def _add_named(service: Service, args: argparse.Namespace) -> bool:
    for name, host, port in args.outstation:
        answer = await service.handle(
            {
                "op": "add",
                "params": {
                    "name": name,
                    "host": host,
                    "port": port,
                    "outstation_address": args.outstation_address,
                    "master_address": args.master_address,
                    "integrity_interval": args.integrity_interval,
                    "event_interval": args.event_interval,
                    **(
                        {}
                        if args.output_interval is None
                        else {"output_interval": args.output_interval or None}
                    ),
                },
            }
        )
        if not answer["ok"]:
            # Added, and shown as not connected, unless it could not be added at all.
            print(f"{name}: {answer['error']['message']}", file=sys.stderr)
            if answer["error"]["kind"] != "connection":
                return False
    return True


async def run_console(args: argparse.Namespace, point_map: PointMap | None = None) -> int:
    """Serve the console until interrupted or told to stop."""
    service = Service()
    try:
        server = HttpServer(service, bind=args.bind, token=args.token)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    demo = Demo(service, point_map, tick=args.tick) if point_map is not None else None
    await server.start()
    try:
        if demo is not None:
            await demo.start()
        if not await _add_named(service, args):
            return 2
        print(f"Satori DNP3 master console at {server.url}", flush=True)
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
        if demo is not None:
            await demo.stop()
        await server.stop()
        await service.close()
    return 0


async def run_service(args: argparse.Namespace) -> int:
    """Serve the line service until interrupted or told to stop."""
    service = Service()
    try:
        server = LineServer(service, bind=args.bind)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    await server.start()
    try:
        if not await _add_named(service, args):
            return 2
        print(
            f"DNP3 master service listening on {args.bind.rpartition(':')[0]}:{server.port}",
            flush=True,
        )
        await service.stopped.wait()
    finally:
        await server.stop()
        await service.close()
    return 0


def _add_outstation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--outstation",
        action="append",
        default=[],
        type=_outstation,
        metavar="NAME=HOST:PORT",
        help="an outstation to add and connect to at startup; may be given more than once",
    )
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    parser.add_argument(
        "--integrity-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="repeat an integrity poll of each outstation this often (default: do not)",
    )
    parser.add_argument(
        "--output-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="repeat a read of output status this often (default: as often as the integrity "
        "poll, which does not include it; 0 for never)",
    )
    parser.add_argument(
        "--event-interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help="repeat an event poll of each outstation this often (default: do not)",
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
        default=DEFAULT_HTTP_BIND,
        help=f"where the console listens (default: {DEFAULT_HTTP_BIND}, this machine only)",
    )
    console.add_argument(
        "--token",
        default=None,
        help="required of every request; needed to listen on anything but this machine",
    )
    console.add_argument("--open", action="store_true", help="open the console in a browser")
    console.add_argument(
        "--demo",
        action="store_true",
        help="also start a simulated IEEE 1815.2 DER and connect to it",
    )
    console.add_argument(
        "--tables",
        default=None,
        help=f"the profile tables file for --demo (default: ${load.TABLES_VARIABLE}, else "
        f"~/.py1815/{load.TABLES_NAME})",
    )
    console.add_argument(
        "--tick", type=float, default=1.0, help="seconds between steps of the simulated DER"
    )
    _add_outstation_options(console)

    serve = commands.add_parser("serve", help="serve the JSON line service, for a test rig")
    serve.add_argument(
        "--bind", default="127.0.0.1:8816", help="where the service listens, on this machine"
    )
    _add_outstation_options(serve)
    return parser


def _interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    point_map: PointMap | None = None
    if args.command == "console" and args.demo:
        try:
            point_map = load.load(args.tables, Composition())
        except (MapError, ValueError, OSError) as error:
            print(str(error), file=sys.stderr)
            return 1
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        if args.command == "console":
            return asyncio.run(run_console(args, point_map))
        return asyncio.run(run_service(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
