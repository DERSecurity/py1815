"""One integrity poll of an outstation, and a report of what it answered.

What ``py1815-master poll`` and ``py1815-der poll`` do: connect, ask for every
event class and then class 0, confirm what asks to be confirmed, disconnect,
and print how much came back and the analog inputs, named from the IEEE
1815.2 profile tables when this machine has them. Nothing is sent but the
poll and its confirmations, so it is safe to point at anything.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import sys
from dataclasses import dataclass

from py1815.decode import DecodedObject, PointType
from py1815.master.api import Outstation
from py1815.master.association import Exchange, Outcome
from py1815.master.tasks import Tasks
from py1815.master.tls import TlsSettings
from py1815.profile import load
from py1815.profile.model import Kind, MapError, PointMap

#: The groups counted in the report's first line, by what they hold.
GROUP_NAMES = {1: "binary inputs", 20: "counters", 21: "frozen counters", 30: "analog inputs"}

#: Analog inputs printed unless told otherwise.
DEFAULT_LIMIT = 12


class PollError(RuntimeError):
    """The outstation could not be reached, or did not answer."""


@dataclass(frozen=True)
class Poll:
    """What an integrity poll returned."""

    exchange: Exchange

    @property
    def fragments(self) -> int:
        return len(self.exchange.fragments)

    @property
    def static(self) -> list[DecodedObject]:
        """The static objects, in the order received."""
        return [each for each in self.exchange.objects if not each.event]

    @property
    def events(self) -> list[DecodedObject]:
        """The events, in the order received."""
        return [each for each in self.exchange.objects if each.event]

    def group(self, group: int) -> list[DecodedObject]:
        """Every static object of one group, in the order received."""
        return [each for each in self.static if each.group == group]

    def find(self, group: int, index: int) -> DecodedObject | None:
        """One static object by group and index, or None if it was not sent."""
        return next((each for each in self.group(group) if each.index == index), None)


async def integrity_poll(
    host: str,
    port: int,
    *,
    outstation_address: int = 1024,
    master_address: int = 1,
    timeout: float = 5.0,
    read_retries: int = 0,
    tls: ssl.SSLContext | None = None,
    server_name: str | None = None,
) -> Poll:
    """Connect, run one integrity poll, confirm what asks for it, and disconnect.

    Raises :class:`PollError` when no connection can be made or nothing is
    answered. A response that stops before its final fragment is returned
    with what did arrive.
    """
    outstation = Outstation(
        "poll",
        host=host,
        port=port,
        outstation_address=outstation_address,
        master_address=master_address,
        response_timeout=timeout,
        connect_timeout=timeout,
        read_retries=read_retries,
        tls=tls,
        server_name=server_name,
        tasks=Tasks.none(),
        confirm=True,
        reconnect=None,
    )
    try:
        await outstation.connect()
    except OSError as error:
        raise PollError(f"cannot connect to {host}:{port}: {error}") from error
    try:
        exchange = await outstation.integrity_poll()
    finally:
        await outstation.close()
    if not exchange.fragments:
        if exchange.outcome is Outcome.ABANDONED:
            raise PollError(f"{host}:{port} closed the connection before answering")
        raise PollError(
            f"no answer from {host}:{port} as outstation {outstation_address} "
            f"to master {master_address}"
        )
    return Poll(exchange)


def report(
    poll: Poll, where: str, point_map: PointMap | None, *, limit: int, every: bool
) -> list[str]:
    """Return the lines that describe a poll: the counts, then the analog inputs."""
    counts = ", ".join(f"{len(poll.group(group))} {name}" for group, name in GROUP_NAMES.items())
    iin = poll.exchange.iin
    assert iin is not None
    lines = [
        f"{where} answered in {poll.fragments} fragment(s): {counts}",
        f"  {len(poll.events)} event(s); indications 0x{iin.first:02X} 0x{iin.second:02X}",
    ]
    if poll.exchange.outcome is not Outcome.COMPLETE:
        lines.append("  the response stopped before its final fragment")
    for unread in poll.exchange.undecoded:
        lines.append(f"  not read past this point: {unread.problem}")

    def live_first(value: DecodedObject) -> tuple[bool, int]:
        # The meter ahead of the nameplate: what moves is what shows the
        # outstation is alive, and an enumeration says little as a number.
        point = point_map.get(Kind.AI, value.index or 0) if point_map else None
        measured = (
            point is not None
            and "meter" in (point.section or "").lower()
            and point.units not in (None, "Enum")
        )
        return (not measured, value.index or 0)

    analogs = [each for each in poll.group(30) if each.point is PointType.ANALOG_INPUT]
    chosen = analogs if every else sorted(analogs, key=live_first)[:limit]
    for value in sorted(chosen, key=lambda each: each.index or 0):
        index = value.index or 0
        number = float(value.value) if isinstance(value.value, (int, float)) else float("nan")
        point = point_map.get(Kind.AI, index) if point_map else None
        if point is None:
            lines.append(f"  AI{index:<6} {number:>14.6g}")
            continue
        units = "" if point.units in (None, "None", "n/a") else f" {point.units}"
        reading = point.from_wire(number)
        lines.append(f"  AI{index:<6} {reading:>14.6g}{units}  {point.name[:60]}")
    return lines


def tls_settings(args: argparse.Namespace) -> TlsSettings | None:
    """Return the TLS settings the ``--tls-*`` flags give, or None for plain TCP."""
    given = {
        "ca": getattr(args, "tls_ca", None),
        "certificate": getattr(args, "tls_certificate", None),
        "key": getattr(args, "tls_key", None),
        "server_name": getattr(args, "tls_server_name", None),
    }
    if not any(value is not None for value in given.values()):
        return None
    return TlsSettings(
        **{name: None if value is None else str(value) for name, value in given.items()}
    )


def add_tls_options(parser: argparse.ArgumentParser) -> None:
    """Add the ``--tls-*`` flags. Any of them given connects over TLS."""
    parser.add_argument(
        "--tls-ca",
        default=None,
        metavar="FILE",
        help="connect over TLS, checking the "
        "outstation against the authorities in this PEM file (default: the system's)",
    )
    parser.add_argument(
        "--tls-certificate",
        default=None,
        metavar="FILE",
        help="connect over TLS, offering this PEM certificate",
    )
    parser.add_argument(
        "--tls-key",
        default=None,
        metavar="FILE",
        help="the certificate's private key, when it is not in the certificate's file",
    )
    parser.add_argument(
        "--tls-server-name",
        default=None,
        metavar="NAME",
        help="the name the outstation's certificate is checked against (default: the host)",
    )


def count(text: str) -> int:
    """Return a whole number of zero or more, for an argument parser."""
    try:
        number = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a whole number") from None
    if number < 0:
        raise argparse.ArgumentTypeError(f"{number} is below zero; a count cannot be negative")
    return number


def add_options(parser: argparse.ArgumentParser, *, default_port: int) -> None:
    """Add the options of a poll command, apart from the link addresses."""
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="seconds to wait for each response"
    )
    parser.add_argument(
        "--read-retries",
        type=count,
        default=0,
        metavar="N",
        help="send the poll again this many times when it is not answered (default: 0)",
    )
    parser.add_argument("--tables", default=None, help="the profile tables, for point names")
    parser.add_argument("--all", action="store_true", help="print every analog input")
    parser.add_argument("--limit", type=count, default=DEFAULT_LIMIT, help="analog inputs to print")
    add_tls_options(parser)


def run(args: argparse.Namespace) -> int:
    """Poll as ``args`` say, print the report, and return the exit status."""
    try:
        tls = tls_settings(args)
        context = None if tls is None else tls.context()
    except (ValueError, OSError) as error:
        print(f"tls: {error}", file=sys.stderr)
        return 2
    try:
        poll = asyncio.run(
            integrity_poll(
                args.host,
                args.port,
                outstation_address=args.outstation_address,
                master_address=args.master_address,
                timeout=args.timeout,
                read_retries=args.read_retries,
                tls=context,
                server_name=None if tls is None else tls.server_name,
            )
        )
    except PollError as error:
        print(str(error), file=sys.stderr)
        return 1
    except ValueError as error:
        # A setting the master refuses, such as two link addresses alike.
        print(str(error), file=sys.stderr)
        return 2
    # Names and units come from the tables when this machine has them; the
    # poll itself needs none, so their absence only shortens the report.
    try:
        point_map: PointMap | None = load.load(args.tables)
    except (MapError, ValueError, OSError):
        point_map = None
    for line in report(
        poll, f"{args.host}:{args.port}", point_map, limit=args.limit, every=args.all
    ):
        print(line)
    return 0


__all__ = ["GROUP_NAMES", "Poll", "PollError", "add_options", "integrity_poll", "report", "run"]
