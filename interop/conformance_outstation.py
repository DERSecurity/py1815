"""A Subset Level 2 outstation that a conformance test harness can drive.

Run by the conformance job, not by the test suite. A certification procedure
has steps a master cannot perform over DNP3: cycle power to the device, change
an input, check that an output operated. A person does those at a test bench.
Here a second connection does them, so the procedures run with nobody present.

The process serves two listeners, both on the loopback interface only:

- the outstation, a Level 2 configuration of this library, over TCP;
- a control channel, which stands for the test bench: it changes the inputs,
  cycles power, changes the settings a power cycle applies, and reports what
  the device holds and which outputs it operated.

The control channel carries one JSON object per line in each direction. Every
request names an operation in ``op``; every answer has ``ok``, and ``error``
when ``ok`` is false. The operations are the methods of :class:`ControlChannel`
named ``op_...``.

Nothing here knows which harness is on the other end or which procedure is
running. The outstation is built from the library's defaults, and what the
control channel reports comes from the device side: the values behind the
inputs, and the writes that reached the outputs.

The point map is invented here. It has enough analog inputs that a class 0
response is longer than one link frame, so a read of it is segmented by the
transport function.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, fields, replace
from typing import Any

from py1815.events import EventClass
from py1815.profile.binding import Binding, Reading
from py1815.profile.model import Kind, Point, PointMap
from py1815.profile.outstation import DerOutstation
from py1815.server import OutstationServer
from py1815.session import Session

logger = logging.getLogger("conformance")

LOOPBACK = "127.0.0.1"

#: The event class each binary input reports in.
BINARY_INPUT_CLASSES = {**dict.fromkeys(range(8), 1), **dict.fromkeys(range(8, 12), 2)}

#: Analog inputs, all in one class. Sixty-four of them make a class 0 response
#: longer than the 249 octets one link frame carries.
ANALOG_INPUTS = tuple(range(64))
ANALOG_INPUT_CLASS = 3

#: An analog input reports an event when it moves further than this from the
#: value it last reported.
DEADBAND = 10

COUNTERS = tuple(range(4))
BINARY_OUTPUTS = tuple(range(10))
ANALOG_OUTPUTS = tuple(range(10))

#: What a cold restart request is answered with: the milliseconds until the
#: device is listening again.
RESTART_DELAY_MS = 1000

#: How long after a cold restart request the power cycle begins. The response
#: to the request has to be written first.
_RESTART_BEGINS_AFTER = 0.2

#: The most operations the device keeps for the control channel to report.
_OPERATED_KEPT = 4096

#: The most octets one control channel request may occupy. A request that
#: changes an input a few thousand times is tens of kilobytes.
_REQUEST_LIMIT = 1 << 20

_KINDS = {"BI": Kind.BI, "AI": Kind.AI, "CTR": Kind.CTR}


def point_map() -> PointMap:
    """Build the point map this device serves."""
    points: list[Point] = []
    points += [
        Point(Kind.BI, index, f"Binary input {index}", event_class=event_class)
        for index, event_class in BINARY_INPUT_CLASSES.items()
    ]
    points += [
        Point(Kind.AI, index, f"Analog input {index}", event_class=ANALOG_INPUT_CLASS)
        for index in ANALOG_INPUTS
    ]
    points += [
        Point(Kind.CTR, index, f"Counter {index}", event_class=0, frozen=True) for index in COUNTERS
    ]
    points += [Point(Kind.BO, index, f"Binary output {index}") for index in BINARY_OUTPUTS]
    points += [Point(Kind.AO, index, f"Analog output {index}") for index in ANALOG_OUTPUTS]
    return PointMap({point.address: point for point in points})


@dataclass(frozen=True)
class Settings:
    """What a power cycle applies. A change takes effect at the next one."""

    #: The link address of the master this outstation serves and reports to.
    master_address: int = 1
    #: Which kinds of point are installed.
    binary_inputs: bool = True
    analog_inputs: bool = True
    counters: bool = True
    binary_outputs: bool = True
    analog_outputs: bool = True
    #: Whether the outstation reports without being asked.
    unsolicited: bool = False
    #: Seconds an unsolicited response waits for its confirmation.
    unsolicited_confirm_timeout: float = 5.0
    #: How many times an unconfirmed unsolicited response is sent again. None
    #: is without limit.
    unsolicited_retries: int | None = None
    #: The largest fragment the outstation sends.
    max_response: int = 2048
    #: Whether the outstation asks the master for the time after it starts.
    need_time: bool = True

    def changed(self, changes: Mapping[str, Any]) -> Settings:
        """Return these settings with *changes* applied. A wrong name or type is refused."""
        known = {field.name: field.type for field in fields(self)}
        for name, value in changes.items():
            if name not in known:
                raise ValueError(f"settings has no {name!r}; it has {', '.join(sorted(known))}")
            wanted = type(getattr(self, name))
            if name == "unsolicited_retries":
                valid = value is None or (isinstance(value, int) and not isinstance(value, bool))
            elif wanted is float:
                valid = isinstance(value, int | float) and not isinstance(value, bool)
            elif wanted is int:
                valid = isinstance(value, int) and not isinstance(value, bool)
            else:
                valid = isinstance(value, wanted)
            if not valid:
                raise ValueError(f"settings.{name} is {value!r}; it must be {known[name]}")
        return replace(self, **changes)


class Device:
    """The device under test: its inputs, its outstation and the listener that serves it."""

    def __init__(
        self,
        *,
        port: int = 20000,
        outstation_address: int = 1024,
        settings: Settings | None = None,
        wall_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    ) -> None:
        self._requested_port = port
        self._outstation_address = outstation_address
        self._wall_ms = wall_ms
        #: The wall clock as the outstation last read it.
        self._wall_read = 0
        self.settings = settings or Settings()
        #: The values behind the inputs. They belong to the plant, not to the
        #: outstation, so a power cycle leaves them as they are.
        self.binary: dict[int, bool] = dict.fromkeys(BINARY_INPUT_CLASSES, False)
        self.analog: dict[int, float] = dict.fromkeys(ANALOG_INPUTS, 0.0)
        self.counters: dict[int, int] = dict.fromkeys(COUNTERS, 0)
        #: When each input last changed, by the wall clock.
        self._changed_at: dict[tuple[Kind, int], int] = {}
        #: Every write that reached an output, oldest first, each numbered.
        self.operated: deque[dict[str, Any]] = deque(maxlen=_OPERATED_KEPT)
        self._operations = 0
        self.power_cycles = 0
        self._outstation: DerOutstation | None = None
        self._session: Session | None = None
        self._server: OutstationServer | None = None
        self._cycling = asyncio.Lock()
        self._restart_timer: asyncio.TimerHandle | None = None
        self._restart_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------- lifecycle

    @property
    def port(self) -> int:
        """The port the outstation listens on. It differs from the one asked for when that was 0."""
        return self._server.port if self._server is not None else self._requested_port

    @property
    def outstation(self) -> DerOutstation:
        """The outstation now running."""
        if self._outstation is None:
            raise RuntimeError("the device is not running")
        return self._outstation

    @property
    def session(self) -> Session:
        """The session now running."""
        if self._session is None:
            raise RuntimeError("the device is not running")
        return self._session

    async def start(self) -> None:
        """Power the device on and return once it accepts connections."""
        async with self._cycling:
            await self._power_on()

    async def stop(self) -> None:
        """Power the device off."""
        if self._restart_timer is not None:
            self._restart_timer.cancel()
            self._restart_timer = None
        task, self._restart_task = self._restart_task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        async with self._cycling:
            await self._power_off()

    async def power_cycle(self, changes: Mapping[str, Any] | None = None) -> None:
        """Power the device off and on, applying *changes* to its settings.

        What a power cycle loses is lost: buffered events, frozen counters,
        output states, an armed select, the time a master wrote and the
        classes it enabled. The inputs keep their values. Returns once the
        device accepts connections again.
        """
        settings = self.settings.changed(changes or {})
        async with self._cycling:
            await self._power_off()
            self.settings = settings
            self.power_cycles += 1
            await self._power_on()

    async def _power_off(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            self._requested_port = server.port
            await server.stop()
        self._outstation = None
        self._session = None

    async def _power_on(self) -> None:
        settings = self.settings
        outstation = DerOutstation(
            point_map(), self._binding(settings), strict=False, level2=True, clock_ms=self._clock_ms
        )
        session = outstation.session(
            outstation_address=self._outstation_address,
            master_address=settings.master_address,
            max_response=settings.max_response,
            need_time=settings.need_time,
            restart_handler=self._cold_restart,
            unsolicited=settings.unsolicited,
            unsolicited_confirm_timeout=settings.unsolicited_confirm_timeout,
            unsolicited_retries=settings.unsolicited_retries,
        )
        # The first poll records where every input stands and buffers nothing.
        outstation.poll()
        server = OutstationServer(session, bind=f"{LOOPBACK}:{self._requested_port}")
        await _start_listening(server)
        self._outstation, self._session, self._server = outstation, session, server

    def _clock_ms(self) -> int:
        """Read the wall clock for the outstation, and keep what it was told."""
        self._wall_read = self._wall_ms()
        return self._wall_read

    def _binding(self, settings: Settings) -> Binding:
        binding = Binding()
        if settings.binary_inputs:
            for index in self.binary:
                binding.read(Kind.BI, index, self._reader(Kind.BI, self.binary, index))
        if settings.analog_inputs:
            for index in self.analog:
                binding.read(
                    Kind.AI, index, self._reader(Kind.AI, self.analog, index), deadband=DEADBAND
                )
        if settings.counters:
            for index in self.counters:
                binding.read(Kind.CTR, index, self._reader(Kind.CTR, self.counters, index))
        if settings.binary_outputs:
            for index in BINARY_OUTPUTS:
                binding.output(Kind.BO, index, self._writer(Kind.BO, index), initial=False)
        if settings.analog_outputs:
            for index in ANALOG_OUTPUTS:
                binding.output(Kind.AO, index, self._writer(Kind.AO, index), initial=0.0)
        return binding

    def _reader(self, kind: Kind, values: Mapping[int, Any], index: int) -> Callable[[], Reading]:
        def read() -> Reading:
            return Reading(values[index], timestamp_ms=self._changed_at.get((kind, index)))

        return read

    def _writer(self, kind: Kind, index: int) -> Callable[[float], None]:
        def write(value: float) -> None:
            self._operations += 1
            self.operated.append(
                {
                    "number": self._operations,
                    "kind": kind.value,
                    "index": index,
                    "value": value,
                    "power_cycle": self.power_cycles,
                }
            )
            logger.info("operated %s%d to %r", kind.value, index, value)

        return write

    def _cold_restart(self) -> int:
        """Begin a power cycle a master asked for, and return the milliseconds it takes."""
        loop = asyncio.get_running_loop()
        if self._restart_timer is not None:
            self._restart_timer.cancel()
        self._restart_timer = loop.call_later(_RESTART_BEGINS_AFTER, self._begin_restart)
        return RESTART_DELAY_MS

    def _begin_restart(self) -> None:
        self._restart_timer = None
        self._restart_task = asyncio.get_running_loop().create_task(self.power_cycle())

    # -------------------------------------------------------------- stimulus

    def change(self, kind: str, index: int, value: bool | int | float) -> dict[str, Any]:
        """Set one input and let the outstation notice.

        Returns what was done: the input, its value, the time the change
        carries by the device's clock, and how many events the outstation
        buffered for it. A counter change buffers none, and neither does an
        analog change inside its deadband.
        """
        which = _KINDS.get(kind)
        if which is None:
            raise ValueError(f"kind is {kind!r}; an input is one of {', '.join(_KINDS)}")
        values: dict[int, Any] = {
            Kind.BI: self.binary,
            Kind.AI: self.analog,
            Kind.CTR: self.counters,
        }[which]
        if index not in values:
            raise ValueError(f"the device has no {kind}{index}")
        if which is Kind.BI:
            if not isinstance(value, bool):
                raise ValueError(f"BI{index} is set to {value!r}; a binary input is true or false")
        elif isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"{kind}{index} is set to {value!r}; it takes a number")
        elif which is Kind.CTR and (value != int(value) or value < 0):
            raise ValueError(
                f"CTR{index} is set to {value!r}; a counter is a whole number, 0 or more"
            )
        outstation = self.outstation
        stamp = self._wall_ms()
        values[index] = int(value) if which is Kind.CTR else value
        self._changed_at[(which, index)] = stamp
        buffered = outstation.poll()
        return {
            "kind": kind,
            "index": index,
            "value": values[index],
            # The outstation's clock is the wall clock moved by whatever time a
            # master wrote. The difference is taken from one reading of each.
            "time_ms": stamp + (outstation.now_ms() - self._wall_read),
            "events": buffered,
        }

    def notify(self) -> None:
        """Have buffered events reported now, if a master enabled their class."""
        if self._server is not None:
            self._server.notify()

    # ---------------------------------------------------------------- report

    def state(self) -> dict[str, Any]:
        """Report what the device holds, from the device side."""
        outstation, session, server = self.outstation, self.session, self._server
        installed = {
            kind.value: [point.index for point in outstation.served(kind)] for kind in Kind
        }
        return {
            "port": self.port,
            "power_cycles": self.power_cycles,
            "settings": asdict(self.settings),
            "installed": installed,
            "binary": _keyed(self.binary),
            "analog": _keyed(self.analog),
            "counters": _keyed(self.counters),
            "binary_outputs": {
                str(index): outstation.value(Kind.BO, index) for index in installed["BO"]
            },
            "analog_outputs": {
                str(index): outstation.value(Kind.AO, index) for index in installed["AO"]
            },
            "event_classes": {
                kind.value: {
                    str(point.index): outstation.event_class(kind, point.index)
                    for point in outstation.served(kind)
                }
                for kind in (Kind.BI, Kind.AI)
            },
            "events_held": {
                str(int(event_class)): outstation.events.count(event_class)
                for event_class in EventClass
            },
            "deadband": DEADBAND,
            "operations": self._operations,
            "operated": list(self.operated),
            "time_ms": outstation.now_ms(),
            "restart_indication": session.restart_indication,
            "need_time": session.need_time,
            "unsolicited_classes": sorted(int(c) for c in session.unsolicited_classes),
            "connected": server is not None and server.connected,
        }


def _keyed(values: Mapping[int, Any]) -> dict[str, Any]:
    """Return a mapping with its indices as text, as JSON keys are."""
    return {str(index): value for index, value in values.items()}


async def _start_listening(server: OutstationServer) -> None:
    """Start a listener, waiting out the moment a port takes to come free after a close."""
    for attempt in range(50):
        try:
            await server.start()
            return
        except OSError:
            if attempt == 49:
                raise
            await asyncio.sleep(0.1)


class ControlChannel:
    """The test bench: a line-oriented JSON listener that drives a :class:`Device`."""

    def __init__(self, device: Device, *, port: int = 0) -> None:
        self._device = device
        self._requested_port = port
        self._server: asyncio.Server | None = None
        self.stopped = asyncio.Event()

    @property
    def port(self) -> int:
        """The port the control channel listens on."""
        if self._server is None or not self._server.sockets:
            return self._requested_port
        bound: int = self._server.sockets[0].getsockname()[1]
        return bound

    async def start(self) -> None:
        """Listen on the loopback interface."""
        self._server = await asyncio.start_server(
            self._handle, LOOPBACK, self._requested_port, limit=_REQUEST_LIMIT
        )

    async def stop(self) -> None:
        """Stop listening."""
        server, self._server = self._server, None
        if server is not None:
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while not self.stopped.is_set():
                try:
                    line = await reader.readline()
                except ValueError:
                    answer: dict[str, Any] = {"ok": False, "error": "the request is too long"}
                    writer.write(json.dumps(answer).encode("utf-8") + b"\n")
                    await writer.drain()
                    return
                if not line:
                    return
                answer = await self.answer(line)
                writer.write(json.dumps(answer).encode("utf-8") + b"\n")
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            return
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def answer(self, line: bytes) -> dict[str, Any]:
        """Carry out one request and return its answer. A failure is an answer, not an exception."""
        try:
            request = json.loads(line)
        except (ValueError, UnicodeDecodeError) as exc:
            return {"ok": False, "error": f"the request is not JSON: {exc}"}
        if not isinstance(request, dict) or not isinstance(request.get("op"), str):
            return {"ok": False, "error": "a request is a JSON object with an 'op'"}
        operation = getattr(self, "op_" + request["op"], None)
        if operation is None:
            return {"ok": False, "error": f"unknown operation {request['op']!r}"}
        try:
            result: dict[str, Any] = await operation(request)
        except (ValueError, TypeError, KeyError, RuntimeError) as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, **result}

    async def op_state(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Report the device's settings, inputs, outputs and operated controls."""
        del request
        return self._device.state()

    async def op_power_cycle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Cycle power, applying any ``settings`` given. Answer once the device listens again."""
        changes = request.get("settings", {})
        if not isinstance(changes, dict):
            raise ValueError("'settings' is an object of setting names and values")
        await self._device.power_cycle(changes)
        return self._device.state()

    async def op_set(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Change inputs, one at a time and in the order given.

        ``changes`` is a list of ``[kind, index, value]``, where kind is
        ``BI``, ``AI`` or ``CTR``. Each change is noticed by the outstation
        before the next is made, so a point changed twice reports two events.
        ``pause_ms`` waits that long between one change and the next.
        """
        changes = request.get("changes")
        if not isinstance(changes, list):
            raise ValueError("'changes' is a list of [kind, index, value]")
        pause = request.get("pause_ms", 0)
        if isinstance(pause, bool) or not isinstance(pause, int | float) or pause < 0:
            raise ValueError("'pause_ms' is a number of milliseconds, 0 or more")
        done = []
        for position, change in enumerate(changes):
            if not isinstance(change, list) or len(change) != 3:
                raise ValueError(f"change {position} is {change!r}; it is [kind, index, value]")
            kind, index, value = change
            if isinstance(index, bool) or not isinstance(index, int):
                raise ValueError(
                    f"change {position} has index {index!r}; an index is a whole number"
                )
            if position and pause:
                await asyncio.sleep(pause / 1000)
            done.append(self._device.change(kind, index, value))
        self._device.notify()
        return {"changes": done}

    async def op_stop(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """End the process."""
        del request
        self.stopped.set()
        return {}


async def main() -> None:
    """Serve the outstation and its control channel until told to stop."""
    parser = argparse.ArgumentParser(description=__doc__.partition("\n")[0])
    parser.add_argument(
        "--port", type=int, default=20000, help="the port the outstation listens on"
    )
    parser.add_argument(
        "--control-port",
        type=int,
        default=0,
        help="the port the control channel listens on; 0 takes any free port and prints it",
    )
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s outstation: %(message)s")

    device = Device(
        port=args.port,
        outstation_address=args.outstation_address,
        settings=Settings(master_address=args.master_address),
    )
    channel = ControlChannel(device, port=args.control_port)
    await device.start()
    await channel.start()
    # The one line on standard output, for the program that started this one.
    print(f"control channel listening on {LOOPBACK}:{channel.port}", flush=True)
    try:
        await channel.stopped.wait()
    finally:
        await channel.stop()
        await device.stop()


if __name__ == "__main__":
    asyncio.run(main())
