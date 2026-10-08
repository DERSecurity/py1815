"""The master as a service: its operations as JSON, for a caller in another process.

One table of operations, each taking a JSON object and returning one. Two
ways in carry the same messages: a line of JSON at a time over a local TCP
socket, for a test rig, and HTTP for a browser, where a request is a POST and
what happens unasked arrives as server-sent events. Neither needs anything the
standard library does not have.

The console speaks only this. Whatever it can do, a script can do with the
same words.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import contextvars
import ipaddress
import json
import logging
import mimetypes
import pathlib
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from py1815.application import FunctionCode
from py1815.control import AnalogOutput
from py1815.decode import DecodedObject, PointType
from py1815.master import requests
from py1815.master.api import Master, Outstation
from py1815.master.association import Exchange, Unsolicited
from py1815.master.capture import CaptureFile
from py1815.master.controls import Mode, Operated, Plan, commands
from py1815.master.store import PointValue
from py1815.master.tasks import WRITING, Tasks
from py1815.master.trace import Entry, Recorder, iin_names
from py1815.objects import AnalogQuality, BinaryQuality, CounterQuality
from py1815.profile.model import Kind, PointMap

logger = logging.getLogger(__name__)

#: Where the console's files are.
CONSOLE_DIRECTORY = pathlib.Path(__file__).parent / "console"

DEFAULT_HTTP_BIND = "127.0.0.1:8815"

#: Objects of one exchange described in full before the rest are only counted.
_OBJECTS_DESCRIBED = 2000

_MAX_REQUEST_BODY = 1 << 20
_MAX_HEADER = 16 << 10

_FLAGS: dict[PointType, type[BinaryQuality] | type[AnalogQuality] | type[CounterQuality]] = {
    PointType.BINARY_INPUT: BinaryQuality,
    PointType.BINARY_OUTPUT: BinaryQuality,
    PointType.COUNTER: CounterQuality,
    PointType.FROZEN_COUNTER: CounterQuality,
    PointType.ANALOG_INPUT: AnalogQuality,
    PointType.ANALOG_OUTPUT: AnalogQuality,
}

_POINT_TYPES = {point.value: point for point in PointType}

#: The point types each kind of profile point is read as.
_KIND_TYPES: dict[Kind, tuple[PointType, ...]] = {
    Kind.BI: (PointType.BINARY_INPUT,),
    Kind.BO: (PointType.BINARY_OUTPUT,),
    Kind.AI: (PointType.ANALOG_INPUT,),
    Kind.AO: (PointType.ANALOG_OUTPUT,),
    # A frozen counter is the counter of the same index, as it stood at a freeze.
    Kind.CTR: (PointType.COUNTER, PointType.FROZEN_COUNTER),
}

Names = Mapping[PointType, Mapping[int, str]]


#: A value an enumeration names: a number, a range of them, or a number and up.
_ENUMERATED = re.compile(r"<\s*(\d+(?:\s*-\s*\d+)?\+?)\s*>")

#: What a name says before it starts listing values, which is not part of it.
_ENUMERATION_LEAD = re.compile(r"[\s.:;,-]*(?:enumeration)?[\s.:;,-]*$", re.IGNORECASE)


def split_enumeration(name: str) -> tuple[str, list[dict[str, str]] | None]:
    """A point's name without the values it lists, and the values apart.

    The profile's tables write an enumerated point's values into its name:
    ``Curve Type. Enumeration: <0> Curve is not defined <2> Volt-Var``. That
    is the right thing to have and the wrong thing to print in a column, so
    this takes it apart: ``("Curve Type", [{"value": "0", "name": "Curve is
    not defined"}, ...])``. A value may be a number, a range (``11-255``) or
    a number and up (``99+``), as the tables have them.

    A name that lists fewer than two values is returned whole, with None. A
    value written in passing, as in ``Default is <3>``, names nothing after
    it and is not an entry: it is left in the name, without its brackets.
    """
    found = list(_ENUMERATED.finditer(name))
    entries: list[tuple[int, str, str]] = []
    for position, token in enumerate(found):
        end = found[position + 1].start() if position + 1 < len(found) else len(name)
        text = name[token.end() : end].strip().lstrip("=:-").strip()
        if text.strip(" .,;:"):
            entries.append((token.start(), "".join(token.group(1).split()), text))
    if len(entries) < 2:
        return name, None
    label = _ENUMERATED.sub(lambda token: token.group(1), name[: entries[0][0]])
    label = _ENUMERATION_LEAD.sub("", label).strip()
    values = [{"value": value, "name": text.rstrip(" .,;")} for _start, value, text in entries]
    return label or name, values


#: Updates a subscriber may fall behind by before the oldest are dropped.
SUBSCRIBER_QUEUE = 10_000

#: Seconds an event stream may take to accept a write before it is closed.
#: A browser that stopped reading would otherwise hold the stream open for ever.
STREAM_WRITE_TIMEOUT = 60.0

#: Whether the operation being handled commanded an outstation.
_commanded: contextvars.ContextVar[bool] = contextvars.ContextVar("commanded", default=False)

#: The longest parameter text written to the log for one command.
_LOGGED_PARAMS = 500


def _outcome(result: Any) -> str:
    """Summarize a command's result for the log."""
    if isinstance(result, Mapping):
        if "accepted" in result:
            return {True: "accepted", False: "refused", None: "not known"}.get(
                result["accepted"], str(result["accepted"])
            )
        if "outcome" in result:
            return str(result["outcome"])
    return "done"


class ControlNotAllowed(Exception):
    """The operation commands an outstation, and this service was not started to."""


class BadRequest(ValueError):
    """A message that does not name an operation, or gives it the wrong things."""


def flag_names(point: PointType | None, flags: int | None) -> list[str] | None:
    """A flag octet as the names of the bits set, or None where there is none."""
    if flags is None:
        return None
    if point is None:
        return [f"0x{flags:02X}"] if flags else []
    return [
        bit.name
        for bit in _FLAGS[point]
        if bit.name is not None and bit.name != "STATE" and flags & bit
    ]


def _number(value: bool | int | float | None) -> bool | int | float | str | None:
    """A value JSON can carry. A float with no number is sent as the word for it."""
    if isinstance(value, float) and value != value:
        return "NaN"
    if isinstance(value, float) and value in (float("inf"), float("-inf")):
        return "Infinity" if value > 0 else "-Infinity"
    return value


def describe_object(decoded: DecodedObject, name: str | None = None) -> dict[str, Any]:
    return {
        "type": decoded.point.value if decoded.point is not None else None,
        "group": decoded.group,
        "variation": decoded.variation,
        "index": decoded.index,
        "name": name,
        "value": _number(decoded.value),
        "flags": flag_names(decoded.point, decoded.flags),
        "time_ms": decoded.time_ms,
        "synchronized": decoded.synchronized,
        "event": decoded.event,
    }


def describe_value(
    index: int, value: PointValue, point: PointType, name: str | None
) -> dict[str, Any]:
    return {
        "index": index,
        "name": name,
        "value": _number(value.value),
        "flags": flag_names(point, value.flags),
        "time_ms": value.time_ms,
        "from_event": value.from_event,
        "group": value.group,
        "variation": value.variation,
        "age": round(time.monotonic() - value.received, 3),
    }


def describe_entry(entry: Entry) -> dict[str, Any]:
    return {
        "id": entry.id,
        "at": entry.at,
        "direction": entry.direction,
        "octets": entry.octets.hex(),
        "link": entry.link,
        "transport": entry.transport,
        "application": entry.application,
        "summary": entry.summary,
    }


class Service:
    """A master, and the operations it answers as JSON."""

    def __init__(
        self,
        master: Master | None = None,
        *,
        allow_control: bool = False,
        capture: CaptureFile | None = None,
    ) -> None:
        """
        Args:
            master: The master to serve. A new one when not given.
            allow_control: Carry out the operations that command an
                outstation: its outputs, its counters, its clock, its restart
                indication, and any request by function code other than a
                read. Off unless asked for. A master that is pointed at real
                equipment should have to be told before it can change it.
                When off, outstations are also added with the automatic
                tasks that write (restart clear, time write) disabled.
            capture: A pcap file to write every frame of every outstation
                added to, as it is sent or received. The service closes it
                when it closes.
        """
        self.master = Master() if master is None else master
        self.allow_control = allow_control
        self.capture_file = capture
        self._recorders: dict[str, Recorder] = {}
        #: Each outstation's listener that writes the capture file, by name.
        self._capture_listeners: dict[str, Callable[[Entry], None]] = {}
        self._names: dict[str, dict[PointType, dict[int, str]]] = {}
        self._profiles: dict[str, PointMap] = {}
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.stopped = asyncio.Event()
        self._operations: dict[str, Callable[[Mapping[str, Any]], Awaitable[Any]]] = {
            "status": self._status,
            "profile": self._profile,
            "add": self._add,
            "remove": self._remove,
            "connect": self._connect,
            "disconnect": self._disconnect,
            "idle": self._idle,
            "scan": self._scan,
            "read": self._read,
            "values": self._values,
            "events": self._events,
            "request": self._request,
            "operate": self._operate,
            "write_time": self._write_time,
            "clear_restart": self._clear_restart,
            "freeze": self._freeze,
            "restart": self._restart,
            "enable_unsolicited": self._enable_unsolicited,
            "disable_unsolicited": self._disable_unsolicited,
            "repeat": self._repeat,
            "trace": self._trace,
            "capture": self._capture,
            "clear": self._clear,
            "stop": self._stop,
        }

    # -------------------------------------------------------------- messages

    @property
    def operations(self) -> tuple[str, ...]:
        """The names of the operations, as a message's ``op`` may give them."""
        return tuple(self._operations)

    async def handle(self, message: Any) -> dict[str, Any]:
        """Answer one message. Never raises: what went wrong is the answer."""
        identifier = message.get("id") if isinstance(message, Mapping) else None
        try:
            if not isinstance(message, Mapping):
                raise BadRequest("a message is a JSON object")
            operation = self._operations.get(str(message.get("op")))
            if operation is None:
                raise BadRequest(
                    f"{message.get('op')!r} is not an operation; one of "
                    + ", ".join(self._operations)
                )
            params = message.get("params") or {}
            if not isinstance(params, Mapping):
                raise BadRequest("params is a JSON object")
            if "outstation" in message and "outstation" not in params:
                params = {**params, "outstation": message["outstation"]}
            _commanded.set(False)
            result = await operation(params)
            if _commanded.get():
                self._audit(str(message.get("op")), params, _outcome(result))
        except ControlNotAllowed as error:
            logger.warning(
                "dnp3 master: refused %s for %s: commanding is off",
                message.get("op") if isinstance(message, Mapping) else None,
                params.get("outstation") if isinstance(params, Mapping) else None,
            )
            return {
                "id": identifier,
                "ok": False,
                "error": {"kind": "not_allowed", "message": str(error)},
            }
        # Busy, which the association raises for a second request while one is
        # outstanding, is deliberately not caught. An outstation takes its
        # requests one at a time through a lock, so no message can cause it; if
        # it is ever raised here the fault is in this library and should be seen.
        except (ValueError, KeyError, TypeError) as error:
            text = str(error.args[0]) if isinstance(error, KeyError) and error.args else str(error)
            return {"id": identifier, "ok": False, "error": {"kind": "request", "message": text}}
        except OSError as error:
            if _commanded.get():
                self._audit(str(message.get("op")), params, f"failed: {error}")
            return {
                "id": identifier,
                "ok": False,
                "error": {"kind": "connection", "message": str(error) or type(error).__name__},
            }
        return {"id": identifier, "ok": True, "result": result}

    @staticmethod
    def _audit(op: str, params: Mapping[str, Any], outcome: str) -> None:
        """Log a command sent to an outstation, with what was asked and what came of it."""
        asked = {key: value for key, value in params.items() if key != "outstation"}
        text = json.dumps(asked, separators=(",", ":"), default=str)
        if len(text) > _LOGGED_PARAMS:
            text = text[:_LOGGED_PARAMS] + "..."
        logger.info(
            "dnp3 master: command %s to %s %s: %s", op, params.get("outstation"), text, outcome
        )

    # ---------------------------------------------------------- subscription

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """A queue that receives everything that happens, until unsubscribed."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: dict[str, Any]) -> None:
        """Send an event to every subscriber.

        A subscriber that has fallen SUBSCRIBER_QUEUE updates behind has
        its waiting updates replaced by one lost event that says how many
        were dropped, and stays subscribed. It can then reload what it shows,
        and memory stays bounded however long it lags.
        """
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                dropped = 1
                while not queue.empty():
                    queue.get_nowait()
                    dropped += 1
                logger.warning(
                    "dnp3 master: a subscriber fell behind; dropped %d update(s)", dropped
                )
                queue.put_nowait({"event": "lost", "dropped": dropped})

    # ----------------------------------------------------------- outstations

    def set_names(self, outstation: str, names: Names) -> None:
        """Give an outstation's points names, for a caller that knows its map."""
        self._names[outstation] = {point: dict(indexed) for point, indexed in names.items()}

    def set_profile(self, outstation: str, point_map: PointMap) -> None:
        """Give an outstation the profile it is meant to serve.

        The whole map, and not only the points the outstation reports. That
        is what lets a caller see the difference: a point of the profile the
        outstation has never reported is one it does not implement, or one
        nobody has read yet, and a master cannot tell which from silence.
        """
        self._profiles[outstation] = point_map
        names: dict[PointType, dict[int, str]] = {point: {} for point in PointType}
        for (kind, index), point in point_map.points.items():
            for point_type in _KIND_TYPES[kind]:
                names[point_type][index] = point.name
        self._names[outstation] = names

    def _name(self, outstation: str, point: PointType | None, index: int | None) -> str | None:
        if point is None or index is None:
            return None
        return self._names.get(outstation, {}).get(point, {}).get(index)

    def _profile_counts(self, outstation: str) -> dict[str, int] | None:
        point_map = self._profiles.get(outstation)
        if point_map is None:
            return None
        counts = {point.value: 0 for point in PointType}
        for kind, _index in point_map.points:
            for point_type in _KIND_TYPES[kind]:
                counts[point_type.value] += 1
        return counts

    def _outstation(self, params: Mapping[str, Any]) -> Outstation:
        name = params.get("outstation")
        if name is None:
            raise BadRequest("the operation needs an outstation")
        try:
            return self.master[str(name)]
        except KeyError:
            raise BadRequest(f"there is no outstation named {name!r}") from None

    def _describe_outstation(self, outstation: Outstation) -> dict[str, Any]:
        last = outstation.last_response
        return {
            "name": outstation.name,
            "host": outstation.host,
            "port": outstation.port,
            "outstation_address": outstation.association.outstation_address,
            "master_address": outstation.association.master_address,
            "connected": outstation.connected,
            "indications": iin_names(last.iin) if last is not None and last.iin else [],
            "last_response_at": outstation.last_response_at,
            "counts": dict(outstation.counts),
            "unsolicited": len(outstation.unsolicited),
            "points": {point.value: len(outstation.store.points(point)) for point in PointType},
            "events": len(outstation.store.events),
            "frames": len(outstation.trace),
            "repeat": outstation.scan_intervals,
            "tasks": outstation.tasks.describe(),
            "tasks_due": list(outstation.tasks_due),
            "reconnect": outstation.reconnect,
            "named": bool(self._names.get(outstation.name)),
            "profile": self._profile_counts(outstation.name),
        }

    def _describe_exchange(self, outstation: Outstation, exchange: Exchange) -> dict[str, Any]:
        objects = [
            describe_object(decoded, self._name(outstation.name, decoded.point, decoded.index))
            for decoded in exchange.objects[:_OBJECTS_DESCRIBED]
        ]
        return {
            "function": exchange.function.name,
            "task": exchange.task,
            "sequence": exchange.sequence,
            "outcome": exchange.outcome.value,
            "fragments": len(exchange.fragments),
            "indications": iin_names(exchange.iin) if exchange.iin is not None else None,
            "objects": objects,
            "object_count": len(exchange.objects),
            "undecoded": [
                {"problem": decoded.problem, "unread": decoded.unread.hex()}
                for decoded in exchange.undecoded
            ],
            "elapsed_ms": round(exchange.elapsed * 1000, 1),
            "request": exchange.request.hex(),
        }

    def attach(self, outstation: Outstation) -> None:
        """Have what happens to an outstation published to subscribers."""
        name = outstation.name

        def on_frame(entry: Entry) -> None:
            self.publish({"event": "frame", "outstation": name, "frame": describe_entry(entry)})

        def on_exchange(exchange: Exchange) -> None:
            described = self._describe_exchange(outstation, exchange)
            self.publish({"event": "exchange", "outstation": name, "exchange": described})

        def on_unsolicited(unsolicited: Unsolicited) -> None:
            objects = [
                describe_object(decoded, self._name(name, decoded.point, decoded.index))
                for decoded in unsolicited.objects
            ]
            self.publish(
                {
                    "event": "unsolicited",
                    "outstation": name,
                    "indications": iin_names(unsolicited.iin),
                    "objects": objects,
                }
            )

        def on_connection(connected: bool) -> None:
            self.publish({"event": "connection", "outstation": name, "connected": connected})

        outstation.trace.listeners.append(on_frame)
        if self.capture_file is not None:
            recorder = Recorder(self.capture_file, outstation.trace, port=outstation.port)
            self._recorders[name] = recorder

            def on_frame_captured(entry: Entry) -> None:
                # A listener's error reaches the code that recorded the frame,
                # which is the receive loop or a request. A full disk must not
                # end the DNP3 connection, so the capture stops instead.
                try:
                    recorder.record(entry)
                except (OSError, ValueError):
                    logger.exception("dnp3 master: writing the capture of %s failed", name)
                    self._stop_capture()

            self._capture_listeners[name] = on_frame_captured
            outstation.trace.listeners.append(on_frame_captured)
        outstation.on_exchange = on_exchange
        outstation.on_unsolicited = on_unsolicited
        outstation.on_connection = on_connection

    # ------------------------------------------------------------ operations

    async def _status(self, _params: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "allow_control": self.allow_control,
            "outstations": [
                self._describe_outstation(outstation)
                for outstation in self.master.outstations.values()
            ],
        }

    async def _profile(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """Every point of the profile an outstation was given, reported or not."""
        outstation = self._outstation(params)
        point_map = self._profiles.get(outstation.name)
        if point_map is None:
            return {"version": None, "points": None}
        points: dict[str, list[dict[str, Any]]] = {point.value: [] for point in PointType}
        for (kind, index), point in sorted(
            point_map.points.items(), key=lambda item: (item[0][0].value, item[0][1])
        ):
            label, enumeration = split_enumeration(point.name)
            for point_type in _KIND_TYPES[kind]:
                points[point_type.value].append(
                    {
                        "index": index,
                        "name": point.name,
                        "label": label,
                        "enumeration": enumeration,
                        "mandatory": point.mandatory,
                        "section": point.section,
                    }
                )
        return {"version": point_map.profile_version, "points": points}

    async def _add(self, params: Mapping[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not name or not isinstance(name, str):
            raise BadRequest("an outstation is added with a name")
        if "host" not in params:
            raise BadRequest("an outstation is added with a host")
        options: dict[str, Any] = {"host": str(params["host"])}
        for key, kind in (
            ("port", int),
            ("outstation_address", int),
            ("master_address", int),
            ("response_timeout", float),
            ("connect_timeout", float),
        ):
            if params.get(key) is not None:
                options[key] = kind(params[key])
        if params.get("confirm") is not None:
            options["confirm"] = bool(params["confirm"])
        if "reconnect" in params:
            given = params["reconnect"]
            options["reconnect"] = None if given is None else float(given)
        options["manual"] = manual = bool(params.get("manual", False))
        options["tasks"] = self._tasks(params.get("tasks"), manual)
        outstation = await self.master.add(name, connect=False, **options)
        self.attach(outstation)
        intervals = {
            "integrity": params.get("integrity_interval"),
            "events": params.get("event_interval"),
            # Output status is not in an integrity poll, so one that is repeated
            # would leave the outputs unread. They are read as often, unless
            # the caller says how often, or says not to with null.
            "outputs": params.get("output_interval", params.get("integrity_interval")),
        }
        for kind_name, interval in intervals.items():
            if interval is not None:
                outstation.repeat_scan(kind_name, float(interval))
        self.publish({"event": "outstations"})
        if params.get("connect", True):
            try:
                await outstation.connect()
            except OSError:
                # Added, and not connected: the caller can see it and try again.
                self.publish({"event": "connection", "outstation": name, "connected": False})
                raise
        return self._describe_outstation(outstation)

    def _tasks(self, given: Any, manual: bool) -> Tasks:
        """Build the task settings for a new outstation from the ``add`` parameters."""
        if given is not None and not isinstance(given, Mapping):
            raise BadRequest("tasks is an object of choices by task")
        tasks = (Tasks.none() if manual else Tasks()).changed(given or {})
        if self.allow_control:
            return tasks
        # A read-only service does not run the tasks that write. Requesting
        # one explicitly is refused; otherwise they are disabled, and the
        # outstation's status shows that.
        for name in WRITING:
            if given and given.get(name):
                self._commanding(f"the {name} task")
        return tasks.reading_only()

    def _stop_capture(self) -> None:
        """Stop writing the capture file for every outstation, after a write failed.

        The file is shared, so a failure for one outstation is a failure for
        all. Open connections are abandoned without their FIN packets, since
        writing more to a failing file would only fail again.
        """
        for name, listener in self._capture_listeners.items():
            with contextlib.suppress(KeyError, ValueError):
                self.master[name].trace.listeners.remove(listener)
        self._capture_listeners.clear()
        for recorder in self._recorders.values():
            recorder.abandon()
        self._recorders.clear()
        if self.capture_file is not None:
            with contextlib.suppress(OSError):
                self.capture_file.close()

    async def _remove(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        await self.master.remove(outstation.name)
        self._capture_listeners.pop(outstation.name, None)
        recorder = self._recorders.pop(outstation.name, None)
        if recorder is not None:
            recorder.close()
        self._names.pop(outstation.name, None)
        self._profiles.pop(outstation.name, None)
        self.publish({"event": "outstations"})
        return {"removed": outstation.name}

    async def _connect(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        await outstation.connect()
        return self._describe_outstation(outstation)

    async def _disconnect(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        await outstation.close()
        self.publish({"event": "connection", "outstation": outstation.name, "connected": False})
        return self._describe_outstation(outstation)

    async def _idle(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """Wait until no automatic task is pending or running."""
        outstation = self._outstation(params)
        await outstation.idle()
        return self._describe_outstation(outstation)

    async def _scan(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        exchange = await outstation.scan(str(params.get("kind", "integrity")))
        return self._describe_exchange(outstation, exchange)

    async def _read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        points = params.get("points")
        if not isinstance(points, Mapping) or not points:
            raise BadRequest("a read names points, by type")
        arguments = {
            "bi": "binary_inputs",
            "bo": "binary_outputs",
            "counter": "counters",
            "frozen": "frozen_counters",
            "ai": "analog_inputs",
            "ao": "analog_outputs",
        }
        named: dict[str, Any] = {}
        for kind, indices in points.items():
            if kind not in arguments:
                raise BadRequest(f"{kind!r} is not a point type; one of {', '.join(arguments)}")
            named[arguments[kind]] = (
                indices if isinstance(indices, str) else [int(index) for index in indices]
            )
        exchange = await outstation.read(**named)
        return self._describe_exchange(outstation, exchange)

    async def _values(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        wanted = params.get("types") or list(_POINT_TYPES)
        result: dict[str, list[dict[str, Any]]] = {}
        for kind in wanted:
            if kind not in _POINT_TYPES:
                raise BadRequest(f"{kind!r} is not a point type")
            point = _POINT_TYPES[kind]
            result[kind] = [
                describe_value(index, value, point, self._name(outstation.name, point, index))
                for index, value in outstation.store.points(point).items()
            ]
        return {"points": result}

    async def _events(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        limit = int(params.get("limit", 500))
        events = outstation.store.events[-limit:] if limit > 0 else ()
        return {
            "events": [
                describe_object(event, self._name(outstation.name, event.point, event.index))
                for event in events
            ],
            "total": len(outstation.store.events),
        }

    async def _request(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        function = params.get("function")
        try:
            code = (
                FunctionCode[function.upper()]
                if isinstance(function, str)
                else FunctionCode(int(function))  # type: ignore[arg-type]
            )
        except (KeyError, ValueError, TypeError):
            raise BadRequest(f"{function!r} is not a function code") from None
        try:
            body = bytes.fromhex(str(params.get("body", "")))
        except ValueError:
            raise BadRequest("body is the octets after the function code, in hexadecimal") from None
        if code not in requests.READING_FUNCTIONS:
            # Any other function code changes the outstation, and this is the
            # one operation that would otherwise send it unasked-about.
            self._commanding(f"a {code.name} request")
        exchange = await outstation.request(code, body)
        return self._describe_exchange(outstation, exchange)

    # ------------------------------------------------------------- commands

    def _commanding(self, what: str) -> None:
        _commanded.set(True)
        if not self.allow_control:
            raise ControlNotAllowed(
                f"{what} commands the outstation, and commanding is off. "
                "Start the service with --allow-control to turn it on."
            )

    def _describe_operated(self, outstation: Outstation, operated: Operated) -> dict[str, Any]:
        statuses = []
        for status in operated.statuses:
            command = status.command
            control = command.control
            if isinstance(control, AnalogOutput):
                value: Any = _number(control.value)
            else:
                value = control.control_code
            statuses.append(
                {
                    "type": command.point.value,
                    "index": command.index,
                    "name": self._name(outstation.name, command.point, command.index),
                    "variation": command.variation,
                    "value": value,
                    "status": None if status.status is None else status.status.name,
                    "echoed": status.echoed,
                }
            )
        return {
            "mode": operated.mode.value,
            "operated": operated.operated,
            "accepted": operated.accepted,
            "statuses": statuses,
            "exchanges": [
                self._describe_exchange(outstation, exchange) for exchange in operated.exchanges
            ],
        }

    async def _operate(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        points = params.get("points")
        if not isinstance(points, Mapping) or not points:
            raise BadRequest("an operate names outputs, by type: bo and ao")
        unknown = set(points) - {"bo", "ao"}
        if unknown:
            raise BadRequest(f"{sorted(unknown)[0]!r} is not an output; bo or ao")
        for kind, named in points.items():
            if not isinstance(named, Mapping):
                raise BadRequest(f"{kind} is an object of values by index")
        variation = params.get("variation")
        # Refused for what is wrong with it before it is refused for not
        # being allowed, so the two are told apart.
        plan = Plan(
            commands(
                points.get("bo"),
                points.get("ao"),
                variation=None if variation is None else int(variation),
            ),
            str(params.get("mode", Mode.DIRECT.value)),
        )
        self._commanding("an operate")
        # Through the outstation's own method, so the plan is carried out in
        # one turn exactly as a caller in Python has it carried out.
        operated = await outstation._carry_out(plan)  # pylint: disable=protected-access
        return self._describe_operated(outstation, operated)

    async def _write_time(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        when = params.get("time_ms")
        if when is not None and (isinstance(when, bool) or not isinstance(when, int)):
            raise BadRequest("time_ms is milliseconds since the epoch, a whole number")
        self._commanding("a time write")
        return self._describe_exchange(outstation, await outstation.write_time(when))

    async def _clear_restart(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        self._commanding("clearing the restart indication")
        return self._describe_exchange(outstation, await outstation.clear_restart())

    async def _freeze(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        self._commanding("a freeze")
        exchange = await outstation.freeze(
            clear=bool(params.get("clear", False)), respond=bool(params.get("respond", True))
        )
        return self._describe_exchange(outstation, exchange)

    async def _restart(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        kind = str(params.get("kind", "cold"))
        if kind not in ("cold", "warm"):
            raise BadRequest(f"{kind!r} is not a restart; cold or warm")
        self._commanding("a restart")
        return self._describe_exchange(outstation, await outstation.restart(kind))

    @staticmethod
    def _classes(params: Mapping[str, Any]) -> list[int]:
        return [int(number) for number in params.get("classes") or (1, 2, 3)]

    async def _enable_unsolicited(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        exchange = await outstation.enable_unsolicited(*self._classes(params))
        return self._describe_exchange(outstation, exchange)

    async def _disable_unsolicited(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        exchange = await outstation.disable_unsolicited(*self._classes(params))
        return self._describe_exchange(outstation, exchange)

    async def _repeat(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        interval = params.get("interval")
        outstation.repeat_scan(
            str(params.get("kind", "integrity")), None if interval is None else float(interval)
        )
        return {"repeat": outstation.scan_intervals}

    async def _trace(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        entries = outstation.trace.since(int(params.get("after", 0)))
        limit = int(params.get("limit", 500))
        return {"frames": [describe_entry(entry) for entry in entries[-limit:]]}

    async def _capture(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """Return the frames kept as a pcap file, in base64 so JSON can carry it."""
        outstation = self._outstation(params)
        after = int(params.get("after", 0))
        frames = len(outstation.trace.since(after))
        pcap = outstation.trace.capture(after=after, port=outstation.port)
        return {"frames": frames, "pcap": base64.b64encode(pcap).decode("ascii")}

    async def _clear(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        what = params.get("what", "trace")
        if what == "trace":
            outstation.trace.clear()
        elif what == "events":
            outstation.store.clear_events()
        else:
            raise BadRequest("what is cleared is the trace or the events")
        return {"cleared": what}

    async def _stop(self, _params: Mapping[str, Any]) -> dict[str, Any]:
        self.stopped.set()
        return {"stopping": True}

    async def close(self) -> None:
        """Close every connection, then end each connection in the capture file and close it."""
        await self.master.close()
        for recorder in self._recorders.values():
            recorder.close()
        self._recorders.clear()
        if self.capture_file is not None:
            self.capture_file.close()


# ------------------------------------------------------------------ transports


def _split_bind(bind: str) -> tuple[str, int]:
    host, separator, port = bind.rpartition(":")
    if not separator or not host:
        raise ValueError(f"{bind!r} is not an address and a port, as in 127.0.0.1:8815")
    return host, int(port)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class LineServer:
    """The service a line of JSON at a time, over a local TCP socket.

    For a test rig. A request is one JSON object on one line, and so is its
    response. A connection that sends ``{"op": "subscribe"}`` is also sent
    what happens unasked, each as a line with an ``event`` field.
    """

    def __init__(self, service: Service, *, bind: str = "127.0.0.1:0") -> None:
        self._service = service
        self._host, self._port = _split_bind(bind)
        if not _is_loopback(self._host):
            raise ValueError(
                f"the line service listens on this machine only, and {self._host} is not it"
            )
        self._server: asyncio.Server | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writing = asyncio.Lock()
        forwarding: asyncio.Task[None] | None = None
        queue: asyncio.Queue[dict[str, Any]] | None = None

        async def send(message: dict[str, Any]) -> None:
            async with writing:
                writer.write(json.dumps(message, separators=(",", ":")).encode() + b"\n")
                await writer.drain()

        async def forward(events: asyncio.Queue[dict[str, Any]]) -> None:
            while True:
                await send(await events.get())

        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                if not line.strip():
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    await send(
                        {
                            "id": None,
                            "ok": False,
                            "error": {"kind": "request", "message": "a line is one JSON object"},
                        }
                    )
                    continue
                if isinstance(message, dict) and message.get("op") == "subscribe":
                    if queue is None:
                        queue = self._service.subscribe()
                        forwarding = asyncio.create_task(forward(queue))
                    await send(
                        {"id": message.get("id"), "ok": True, "result": {"subscribed": True}}
                    )
                    continue
                await send(await self._service.handle(message))
        except (OSError, asyncio.IncompleteReadError):
            return
        finally:
            if forwarding is not None:
                forwarding.cancel()
            if queue is not None:
                self._service.unsubscribe(queue)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


_REASONS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    413: "Payload Too Large",
}


class HttpServer:
    """The service over HTTP, and the console's files.

    ``POST /api/<operation>`` takes an operation's parameters and returns its
    answer, and ``POST /api`` takes a whole message that names its operation.
    ``GET /events`` is a stream of server-sent events. Everything else is a
    file of the console, among them ``/openapi.json``, which describes the
    routes.

    It listens on this machine unless told otherwise, and told otherwise it
    requires a token of every request to the service. A request is refused
    unless it comes
    from a page this server served: a browser will carry a request from any
    page to a local port, and a tool pointed at real equipment must not take
    one.
    """

    def __init__(
        self,
        service: Service,
        *,
        bind: str = DEFAULT_HTTP_BIND,
        token: str | None = None,
        without_token: bool = False,
        directory: pathlib.Path = CONSOLE_DIRECTORY,
    ) -> None:
        """
        Args:
            service: The service to serve.
            bind: The address and port to listen on.
            token: Required of every request to the service, when given.
            without_token: Listen beyond this machine with no token. For a
                container, whose own network is not the one it is published
                on: there, what decides who can reach the port is how it was
                published, and the caller is saying that it was published
                narrowly. A request still has to name this machine as its
                host, so a page elsewhere cannot be pointed at it.
            directory: Where the console's files are.
        """
        self._service = service
        self._host, self._port = _split_bind(bind)
        if not _is_loopback(self._host) and not token and not without_token:
            raise ValueError(
                f"listening on {self._host} is listening to other machines, and needs a token"
            )
        self._token = token
        self._directory = directory
        self._server: asyncio.Server | None = None
        self._streams: set[asyncio.Task[None]] = set()

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    @property
    def url(self) -> str:
        """Where to open the console, with the token when there is one.

        An address that means "every interface" is not one a browser can go
        to, so this machine's own name stands in for it.
        """
        host = "localhost" if self._host in ("0.0.0.0", "::") else self._host
        host = f"[{host}]" if ":" in host else host
        suffix = f"/?token={self._token}" if self._token else "/"
        return f"http://{host}:{self.port}{suffix}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            for stream in list(self._streams):
                stream.cancel()
            await self._server.wait_closed()
            self._server = None

    # ------------------------------------------------------------- requests

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        try:
            await self._serve(reader, writer, task)
        except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            pass
        except asyncio.CancelledError:
            pass
        finally:
            if task is not None:
                self._streams.discard(task)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        task: asyncio.Task[None] | None,
    ) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        if len(head) > _MAX_HEADER:
            return await self._respond(writer, 400, "the request header is too large")
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, _version = lines[0].split(" ")
        except ValueError:
            return await self._respond(writer, 400, "that is not an HTTP request")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        url = urlsplit(target)
        query = parse_qs(url.query)

        refusal = self._refusal(headers, query, url.path)
        if refusal is not None:
            return await self._respond(writer, *refusal)

        if url.path == "/api" or url.path.startswith("/api/"):
            if method != "POST":
                return await self._respond(writer, 405, "the service is asked with POST")
            if headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return await self._respond(writer, 400, "a message is sent as application/json")
            length = int(headers.get("content-length", "0"))
            if length > _MAX_REQUEST_BODY:
                return await self._respond(writer, 413, "the message is too large")
            body = await reader.readexactly(length)
            try:
                sent = json.loads(body) if body.strip() else None
            except ValueError:
                return await self._respond(writer, 400, "the message is not JSON")
            if url.path == "/api":
                # One message, naming its operation: the form the line service takes.
                message = sent
            else:
                # A route for each operation, whose body is its parameters.
                operation = url.path.removeprefix("/api/")
                if operation not in self._service.operations:
                    return await self._respond(writer, 404, "there is no such operation")
                if sent is not None and not isinstance(sent, dict):
                    return await self._respond(writer, 400, "parameters are a JSON object")
                message = {"op": operation, "params": sent or {}}
            answer = await self._service.handle(message)
            return await self._respond_json(writer, answer)

        if method != "GET":
            return await self._respond(writer, 405, "that is read with GET")
        if url.path == "/events":
            if task is not None:
                self._streams.add(task)
            return await self._events(writer)
        return await self._file(writer, url.path)

    def _refusal(
        self, headers: Mapping[str, str], query: Mapping[str, list[str]], path: str
    ) -> tuple[int, str] | None:
        host = headers.get("host", "")
        origin = headers.get("origin")
        if origin is not None and urlsplit(origin).netloc != host:
            return 403, "the request comes from another site"
        if self._token is None:
            # Listening on this machine only. A name that resolves here but is
            # not this machine's own is how another site reaches a local port.
            name = host.rsplit(":", 1)[0].strip("[]")
            if not _is_loopback(name):
                return 403, "the request names a host this server is not"
            return None
        if not (path == "/api" or path.startswith("/api/") or path == "/events"):
            # The console's own files. They are the same for everyone and say
            # nothing about any outstation, and a page cannot put a token on
            # the stylesheet and script it links to. What the token guards is
            # the service: every operation, and the stream of what happens.
            return None
        offered = headers.get("authorization", "").removeprefix("Bearer ").strip()
        offered = offered or (query.get("token") or [""])[0]
        if not secrets.compare_digest(offered.encode(), self._token.encode()):
            return 401, "the token is missing or wrong"
        return None

    async def _respond(self, writer: asyncio.StreamWriter, status: int, text: str) -> None:
        await self._send(writer, status, "text/plain; charset=utf-8", text.encode())

    async def _respond_json(self, writer: asyncio.StreamWriter, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        await self._send(writer, 200, "application/json", body)

    @staticmethod
    async def _send(
        writer: asyncio.StreamWriter, status: int, content_type: str, body: bytes
    ) -> None:
        head = (
            f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(head.encode("latin-1") + body)
        await writer.drain()

    async def _file(self, writer: asyncio.StreamWriter, path: str) -> None:
        name = "index.html" if path in ("", "/") else path.lstrip("/")
        # Only a file that is in the console's own directory, by its own name:
        # nothing in the path is followed.
        served = {entry.name: entry for entry in self._directory.iterdir() if entry.is_file()}
        entry = served.get(name)
        if entry is None:
            return await self._respond(writer, 404, "there is no such file")
        content_type = mimetypes.guess_type(entry.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type.endswith("javascript"):
            content_type += "; charset=utf-8"
        await self._send(writer, 200, content_type, entry.read_bytes())

    async def _events(self, writer: asyncio.StreamWriter) -> None:
        queue = self._service.subscribe()
        try:
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/event-stream\r\n"
                b"Cache-Control: no-store\r\n"
                b"Connection: close\r\n\r\n"
                b": connected\n\n"
            )
            await writer.drain()
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), 15.0)
                except TimeoutError:
                    # A comment, so a connection nobody is writing to is seen
                    # to have gone away.
                    writer.write(b": waiting\n\n")
                else:
                    payload = json.dumps(event, separators=(",", ":"))
                    writer.write(f"data: {payload}\n\n".encode())
                try:
                    await asyncio.wait_for(writer.drain(), STREAM_WRITE_TIMEOUT)
                except TimeoutError:
                    # The browser stopped reading. Close the stream: an
                    # EventSource opens a new one, and the console reloads.
                    logger.warning(
                        "dnp3 master: closed an event stream that stopped reading for %g s",
                        STREAM_WRITE_TIMEOUT,
                    )
                    return
        finally:
            self._service.unsubscribe(queue)
