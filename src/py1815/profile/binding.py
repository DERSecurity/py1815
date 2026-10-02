"""Binding: how a caller says where each point's value comes from.

A point is bound by callables, one per direction (D38). An input is bound to
something that returns its value; an output is bound to something that
accepts one. Everything between that and the wire -- scaling, flags, class 0,
events, the echo of a control -- is the builder's, so a simulator and a data
store bind the same way and neither touches an object encoder.

Values cross this interface in engineering units: watts, volts, percent, a
boolean. The tables say how each travels, and that conversion is not the
caller's to repeat.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum

from py1815.control import CommandStatus
from py1815.profile.model import Address, Kind


class Quality(Enum):
    """What a source knows about the value it is handing over.

    Four states, because four have a representation on the wire. A value
    that is merely old has none -- static objects carry no timestamp -- so a
    source decides for itself when old becomes ``COMM_LOST``.
    """

    GOOD = "good"
    #: The source cannot be reached; the value is the last one it gave.
    COMM_LOST = "comm-lost"
    #: Nothing has been read since this outstation started.
    NEVER_READ = "never-read"
    #: The value is there and is not in effect: it belongs to a function
    #: that is disabled. Reported with no flag set at all.
    OFFLINE = "offline"


@dataclass(frozen=True)
class Reading:
    """One value from a source, with what the source knows about it."""

    value: float | bool
    quality: Quality = Quality.GOOD
    #: When the source measured it, in milliseconds since the Unix epoch, UTC.
    #: None means "now", which is right for a value computed on demand.
    timestamp_ms: int | None = None


#: What a read binding returns: a :class:`Reading`, or a bare value that is
#: taken to be good and current.
Reader = Callable[[], "Reading | float | bool"]

#: What a write binding does with a commanded value, and how it answers. None
#: is accepted as success, so a binding that only stores a value need not say so.
Writer = Callable[[float], "CommandStatus | None"]


@dataclass(frozen=True)
class Output:
    """One bound output."""

    #: Called on operate, never on select. None means the value is stored and
    #: reported back, which is all a plain setting needs.
    apply: Writer | None = None
    #: What the output's status, and the input that mirrors it, report before
    #: any write. None reports the point as never read.
    initial: float | bool | None = None
    #: Checked on select and again on operate, before ``apply``. Returns the
    #: status to refuse with, or None to allow. For a refusal that depends on
    #: state rather than on the value's range, which the tables already bound.
    check: Callable[[float], CommandStatus | None] | None = None
    #: Where the output's status comes from, when it is not simply the last
    #: value written. For an output that is a window onto something else: one
    #: of a multiplexed curve's points shows whichever curve is selected.
    status: Reader | None = None


class Binding:
    """Every point a caller serves, and how.

    Built up by calls and handed to the builder, which reads it once. Binding
    the same address twice is refused: the second binding would silently
    replace the first, and the caller that wrote both believes both are live.
    """

    def __init__(self) -> None:
        self.readers: dict[Address, Reader] = {}
        self.outputs: dict[Address, Output] = {}
        #: Event deadbands, in transmitted units. An analog input absent from
        #: here reports every change of its transmitted value, unless an
        #: event policy gives it a deadband.
        self.deadbands: dict[int, float] = {}

    def read(
        self, kind: Kind, index: int, reader: Reader, *, deadband: float | None = None
    ) -> None:
        """Bind an input (binary, analog or counter) to where its value comes from."""
        if kind.is_output:
            raise ValueError(f"{kind.value}{index} is an output; bind it with output()")
        self._claim((kind, index), self.readers)
        self.readers[(kind, index)] = reader
        if deadband is not None:
            if kind is not Kind.AI:
                raise ValueError("only an analog input has a deadband")
            self.deadbands[index] = deadband

    def output(
        self,
        kind: Kind,
        index: int,
        apply: Writer | None = None,
        *,
        initial: float | bool | None = None,
        check: Callable[[float], CommandStatus | None] | None = None,
        status: Reader | None = None,
    ) -> None:
        """Bind an output (binary or analog) to what a command on it does."""
        if not kind.is_output:
            raise ValueError(f"{kind.value}{index} is an input; bind it with read()")
        self._claim((kind, index), self.outputs)
        self.outputs[(kind, index)] = Output(
            apply=apply, initial=initial, check=check, status=status
        )

    @staticmethod
    def _claim(address: Address, table: Mapping[Address, object]) -> None:
        if address in table:
            raise ValueError(f"{address[0].value}{address[1]} is already bound")
