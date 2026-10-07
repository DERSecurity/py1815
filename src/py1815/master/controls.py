"""Commands on outputs: what is sent, in what order, and what came of it.

A control is the one request a master makes that it must not get wrong and
must not repeat. So this module does three things and nothing else. It turns
what a caller asked for into the objects that travel, refusing anything that
cannot be carried before a frame is built. It says which request follows
which: a select is followed by an operate only when the outstation echoed
every control back unchanged and accepted each one. And it reads the answer
into a status for each control.

Nothing here retries. A response that never came is reported as one that never
came, and whether to send the control again is the caller's to decide, because
only the caller knows whether operating twice is harmless.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from itertools import groupby
from typing import Any

from py1815.application import FunctionCode, QualifierCode
from py1815.control import (
    GROUP_ANALOG_OUTPUT_COMMAND,
    GROUP_BINARY_OUTPUT_COMMAND,
    AnalogOutput,
    CommandStatus,
    ControlError,
    ControlRelayOutputBlock,
    OperationType,
    TripCloseCode,
    decode_control,
    encode_control,
)
from py1815.decode import PointType
from py1815.master.association import Exchange

_INT16 = (-(1 << 15), (1 << 15) - 1)
_INT32 = (-(1 << 31), (1 << 31) - 1)


class Mode(Enum):
    """How a control is sent."""

    #: Direct operate: one request, answered with a status for each control.
    DIRECT = "direct"
    #: Select, then operate: the outstation is asked whether it would, and
    #: told to only if it said yes to everything.
    SELECT = "select"
    #: Direct operate with no acknowledgment: one request, and no answer.
    DIRECT_NO_ACK = "direct_no_ack"


#: What a binary output can be told by name. A latch holds; a pulse, a trip
#: and a close are momentary, and what an outstation does with each is its own.
OPERATIONS: dict[str, tuple[OperationType, TripCloseCode]] = {
    "latch_on": (OperationType.LATCH_ON, TripCloseCode.NUL),
    "latch_off": (OperationType.LATCH_OFF, TripCloseCode.NUL),
    "pulse_on": (OperationType.PULSE_ON, TripCloseCode.NUL),
    "pulse_off": (OperationType.PULSE_OFF, TripCloseCode.NUL),
    "trip": (OperationType.PULSE_ON, TripCloseCode.TRIP),
    "close": (OperationType.PULSE_ON, TripCloseCode.CLOSE),
}


@dataclass(frozen=True)
class Command:
    """One control, as it will travel."""

    point: PointType
    index: int
    control: ControlRelayOutputBlock | AnalogOutput

    @property
    def group(self) -> int:
        binary = isinstance(self.control, ControlRelayOutputBlock)
        return GROUP_BINARY_OUTPUT_COMMAND if binary else GROUP_ANALOG_OUTPUT_COMMAND

    @property
    def variation(self) -> int:
        return 1 if isinstance(self.control, ControlRelayOutputBlock) else self.control.variation

    @property
    def encoded(self) -> bytes:
        """The object's octets, with the status a request carries: none."""
        return encode_control(self.control)


def _index(index: Any) -> int:
    try:
        number = int(index)
    except (TypeError, ValueError):
        raise ValueError(f"{index!r} is not a point index") from None
    if not 0 <= number <= 0xFFFF:
        raise ValueError(f"index {number} is not 0 to 65535")
    return number


def binary(index: Any, value: Any) -> Command:
    """A command on a binary output.

    ``value`` is true or false for a latch on or off, one of the names in
    :data:`OPERATIONS`, a mapping with an ``operation`` and optionally a
    ``count``, ``on_time_ms`` and ``off_time_ms``, or a control relay output
    block made elsewhere.
    """
    if isinstance(value, ControlRelayOutputBlock):
        return Command(PointType.BINARY_OUTPUT, _index(index), value)
    options: dict[str, int] = {}
    if isinstance(value, Mapping):
        unknown = set(value) - {"operation", "count", "on_time_ms", "off_time_ms"}
        if unknown:
            raise ValueError(f"a binary output command has no {sorted(unknown)[0]!r}")
        options = {name: int(value[name]) for name in value if name != "operation"}
        value = value.get("operation")
    if isinstance(value, bool):
        value = "latch_on" if value else "latch_off"
    if not isinstance(value, str) or value.lower() not in OPERATIONS:
        raise ValueError(
            f"{value!r} is not something a binary output can be told; true, false, "
            f"or one of {', '.join(OPERATIONS)}"
        )
    operation, trip_close = OPERATIONS[value.lower()]
    try:
        block = ControlRelayOutputBlock.build(
            operation,
            trip_close=trip_close,
            count=options.get("count", 1),
            on_time_ms=options.get("on_time_ms", 0),
            off_time_ms=options.get("off_time_ms", 0),
        )
        command = Command(PointType.BINARY_OUTPUT, _index(index), block)
        _ = command.encoded
    except (ControlError, struct.error) as error:
        raise ValueError(f"binary output {index}: {error}") from None
    return command


def _variation_for(value: float) -> int:
    """The narrowest variation that carries a value as it was given.

    A whole number travels as an integer, in 16 bits when it fits, since that
    is the variation every outstation takes. Anything else travels as a
    float. An outstation that scales its points reads the two differently: an
    integer is the transmitted value and a float the engineering one.
    """
    if float(value).is_integer():
        whole = int(value)
        if _INT16[0] <= whole <= _INT16[1]:
            return 2
        if _INT32[0] <= whole <= _INT32[1]:
            return 1
    return 3


def analog(index: Any, value: Any, variation: int | None = None) -> Command:
    """A command on an analog output.

    ``value`` is a number, a numeric string, or an analog output made
    elsewhere. ``variation`` is 1 or 2 for a 32- or 16-bit integer and 3 or 4
    for a single or double float; left out, the narrowest that carries the
    value is used.
    """
    if isinstance(value, AnalogOutput):
        return Command(PointType.ANALOG_OUTPUT, _index(index), value)
    if isinstance(value, bool):
        raise ValueError(f"analog output {index} takes a number, not {value!r}")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"analog output {index} takes a number, not {value!r}") from None
    chosen = _variation_for(number) if variation is None else int(variation)
    try:
        command = Command(PointType.ANALOG_OUTPUT, _index(index), AnalogOutput(number, chosen))
        _ = command.encoded
    except ControlError as error:
        raise ValueError(f"analog output {index}: {error}") from None
    return command


def commands(
    binary_outputs: Mapping[Any, Any] | None = None,
    analog_outputs: Mapping[Any, Any] | None = None,
    *,
    variation: int | None = None,
) -> tuple[Command, ...]:
    """The commands for outputs named by index: binary first, each in the order given."""
    made = [binary(index, value) for index, value in (binary_outputs or {}).items()]
    made += [analog(index, value, variation) for index, value in (analog_outputs or {}).items()]
    if not made:
        raise ValueError("an operate names at least one output")
    return tuple(made)


def encode(controls: Sequence[Command]) -> bytes:
    """The object headers and objects of a control request, in the order given.

    Controls of one group and variation that stand together share a header.
    Each object is prefixed by its index, in one octet where every index of
    the header fits and in two where one does not.
    """
    body = bytearray()
    for (group, variation), run in groupby(controls, key=lambda c: (c.group, c.variation)):
        together = list(run)
        narrow = len(together) <= 0xFF and all(command.index <= 0xFF for command in together)
        if narrow:
            body += bytes([group, variation, QualifierCode.UINT8_COUNT_UINT8_INDEX, len(together)])
        else:
            body += struct.pack(
                "<BBBH", group, variation, QualifierCode.UINT16_COUNT_UINT16_INDEX, len(together)
            )
        for command in together:
            body += struct.pack("<B" if narrow else "<H", command.index) + command.encoded
    return bytes(body)


@dataclass(frozen=True)
class PointStatus:
    """What an outstation said about one control."""

    command: Command
    #: The status it answered with, or None if the response did not carry
    #: this control back at all.
    status: CommandStatus | None
    #: Whether what came back was the control as sent, apart from its status.
    #: A master is to check this: an echo that differs is not an answer to
    #: the request that was made.
    echoed: bool

    @property
    def accepted(self) -> bool:
        return self.echoed and self.status is CommandStatus.SUCCESS


def read_statuses(controls: Sequence[Command], exchange: Exchange) -> tuple[PointStatus, ...]:
    """Each control's status, from the objects a response echoed."""
    echoes = [
        decoded
        for decoded in exchange.objects
        if decoded.group in (GROUP_BINARY_OUTPUT_COMMAND, GROUP_ANALOG_OUTPUT_COMMAND)
    ]
    statuses = []
    for command in controls:
        match = next(
            (
                echo
                for echo in echoes
                if (echo.group, echo.variation, echo.index)
                == (command.group, command.variation, command.index)
            ),
            None,
        )
        if match is None:
            statuses.append(PointStatus(command, None, False))
            continue
        # An index may be commanded twice in one request, and each echo
        # answers one of them, in order.
        echoes.remove(match)
        try:
            status = decode_control(match.group, match.variation, match.raw).status
        except ControlError:
            statuses.append(PointStatus(command, None, False))
            continue
        statuses.append(PointStatus(command, status, match.raw[:-1] == command.encoded[:-1]))
    return tuple(statuses)


@dataclass(frozen=True)
class Operated:
    """A control request, or the two of a select and operate, and what came of them."""

    mode: Mode
    commands: tuple[Command, ...]
    #: Each exchange made, in order: one, or a select and then an operate.
    exchanges: tuple[Exchange, ...]
    #: Each control's status, from the last response that carried any.
    statuses: tuple[PointStatus, ...]

    @property
    def operated(self) -> bool:
        """Whether a request that operates was sent.

        False for a select the outstation refused, after which no operate is
        sent. True says only that it was sent, not that it was acted on.
        """
        return bool(self.exchanges) and self.exchanges[-1].function is not FunctionCode.SELECT

    @property
    def accepted(self) -> bool | None:
        """Whether the outstation accepted every control: yes, no, or not known.

        None when it never said: the request takes no acknowledgment, or the
        response did not arrive. That is not a refusal, and the output may
        have been operated.
        """
        if not self.operated:
            return False
        last = self.exchanges[-1]
        if not last.complete:
            return None
        return all(status.accepted for status in self.statuses)

    def status(self, point: PointType | str, index: int) -> CommandStatus | None:
        """The status of the control on one output, or None if there was none."""
        wanted = PointType(point)
        for status in self.statuses:
            if status.command.point is wanted and status.command.index == index:
                return status.status
        return None


class Plan:
    """The requests of one operation, decided one at a time.

    Whatever carries the requests asks what to send next and is told, so a
    master on a socket and one wired to a session follow the same rule for
    when a select is followed by an operate.
    """

    def __init__(self, controls: Sequence[Command], mode: Mode | str = Mode.DIRECT) -> None:
        if not controls:
            raise ValueError("an operate names at least one output")
        try:
            self.mode = Mode(mode)
        except ValueError:
            names = ", ".join(each.value for each in Mode)
            raise ValueError(f"{mode!r} is not a way to operate; one of {names}") from None
        self.commands = tuple(controls)
        self.body = encode(self.commands)

    def next(self, done: Sequence[Exchange]) -> tuple[FunctionCode, bytes] | None:
        """The request to make after those already made, or None when there is none."""
        if not done:
            first = {
                Mode.DIRECT: FunctionCode.DIRECT_OPERATE,
                Mode.SELECT: FunctionCode.SELECT,
                Mode.DIRECT_NO_ACK: FunctionCode.DIRECT_OPERATE_NR,
            }[self.mode]
            return first, self.body
        if self.mode is Mode.SELECT and len(done) == 1 and self._selected(done[0]):
            return FunctionCode.OPERATE, self.body
        return None

    def _selected(self, select: Exchange) -> bool:
        return select.complete and all(
            status.accepted for status in read_statuses(self.commands, select)
        )

    def result(self, done: Sequence[Exchange]) -> Operated:
        """What the exchanges made amount to."""
        statuses: tuple[PointStatus, ...] = tuple(
            PointStatus(command, None, False) for command in self.commands
        )
        for exchange in reversed(done):
            if exchange.fragments:
                statuses = read_statuses(self.commands, exchange)
                break
        return Operated(self.mode, self.commands, tuple(done), statuses)
