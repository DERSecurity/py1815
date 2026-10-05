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
import contextlib
import ipaddress
import json
import logging
import mimetypes
import pathlib
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from py1815.application import FunctionCode
from py1815.decode import DecodedObject, PointType
from py1815.master.api import Master, Outstation
from py1815.master.association import Exchange, Unsolicited
from py1815.master.store import PointValue
from py1815.master.trace import Entry, iin_names
from py1815.objects import AnalogQuality, BinaryQuality, CounterQuality

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

Names = Mapping[PointType, Mapping[int, str]]


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

    def __init__(self, master: Master | None = None) -> None:
        self.master = Master() if master is None else master
        self._names: dict[str, dict[PointType, dict[int, str]]] = {}
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.stopped = asyncio.Event()
        self._operations: dict[str, Callable[[Mapping[str, Any]], Awaitable[Any]]] = {
            "status": self._status,
            "add": self._add,
            "remove": self._remove,
            "connect": self._connect,
            "disconnect": self._disconnect,
            "scan": self._scan,
            "read": self._read,
            "values": self._values,
            "events": self._events,
            "request": self._request,
            "enable_unsolicited": self._enable_unsolicited,
            "disable_unsolicited": self._disable_unsolicited,
            "repeat": self._repeat,
            "trace": self._trace,
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
            result = await operation(params)
        except (ValueError, KeyError, TypeError) as error:
            text = str(error.args[0]) if isinstance(error, KeyError) and error.args else str(error)
            return {"id": identifier, "ok": False, "error": {"kind": "request", "message": text}}
        except OSError as error:
            return {
                "id": identifier,
                "ok": False,
                "error": {"kind": "connection", "message": str(error) or type(error).__name__},
            }
        return {"id": identifier, "ok": True, "result": result}

    # ---------------------------------------------------------- subscription

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """A queue that receives everything that happens, until unsubscribed."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10_000)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: dict[str, Any]) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # A subscriber that stopped reading is dropped, not waited for.
                self._subscribers.discard(queue)

    # ----------------------------------------------------------- outstations

    def set_names(self, outstation: str, names: Names) -> None:
        """Give an outstation's points names, for a caller that knows its map."""
        self._names[outstation] = {point: dict(indexed) for point, indexed in names.items()}

    def _name(self, outstation: str, point: PointType | None, index: int | None) -> str | None:
        if point is None or index is None:
            return None
        return self._names.get(outstation, {}).get(point, {}).get(index)

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
            "named": bool(self._names.get(outstation.name)),
        }

    def _describe_exchange(self, outstation: Outstation, exchange: Exchange) -> dict[str, Any]:
        objects = [
            describe_object(decoded, self._name(outstation.name, decoded.point, decoded.index))
            for decoded in exchange.objects[:_OBJECTS_DESCRIBED]
        ]
        return {
            "function": exchange.function.name,
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
        outstation.on_exchange = on_exchange
        outstation.on_unsolicited = on_unsolicited
        outstation.on_connection = on_connection

    # ------------------------------------------------------------ operations

    async def _status(self, _params: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "outstations": [
                self._describe_outstation(outstation)
                for outstation in self.master.outstations.values()
            ]
        }

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
        outstation = await self.master.add(name, connect=False, **options)
        self.attach(outstation)
        for kind_name, key in (("integrity", "integrity_interval"), ("events", "event_interval")):
            if params.get(key) is not None:
                outstation.repeat_scan(kind_name, float(params[key]))
        self.publish({"event": "outstations"})
        if params.get("connect", True):
            try:
                await outstation.connect()
            except OSError:
                # Added, and not connected: the caller can see it and try again.
                self.publish({"event": "connection", "outstation": name, "connected": False})
                raise
        return self._describe_outstation(outstation)

    async def _remove(self, params: Mapping[str, Any]) -> dict[str, Any]:
        outstation = self._outstation(params)
        await self.master.remove(outstation.name)
        self._names.pop(outstation.name, None)
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
        exchange = await outstation.request(code, body)
        return self._describe_exchange(outstation, exchange)

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
        await self.master.close()


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

    ``POST /api`` takes a message and returns its answer. ``GET /events`` is a
    stream of server-sent events. Everything else is a file of the console.

    It listens on this machine unless told otherwise, and told otherwise it
    requires a token on every request. A request is refused unless it comes
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
        directory: pathlib.Path = CONSOLE_DIRECTORY,
    ) -> None:
        self._service = service
        self._host, self._port = _split_bind(bind)
        if not _is_loopback(self._host) and not token:
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
        host = f"[{self._host}]" if ":" in self._host else self._host
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

        refusal = self._refusal(headers, query)
        if refusal is not None:
            return await self._respond(writer, *refusal)

        if url.path == "/api":
            if method != "POST":
                return await self._respond(writer, 405, "the service is asked with POST")
            if headers.get("content-type", "").split(";")[0].strip() != "application/json":
                return await self._respond(writer, 400, "a message is sent as application/json")
            length = int(headers.get("content-length", "0"))
            if length > _MAX_REQUEST_BODY:
                return await self._respond(writer, 413, "the message is too large")
            body = await reader.readexactly(length)
            try:
                message = json.loads(body)
            except ValueError:
                return await self._respond(writer, 400, "the message is not JSON")
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
        self, headers: Mapping[str, str], query: Mapping[str, list[str]]
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
                await writer.drain()
        finally:
            self._service.unsubscribe(queue)
