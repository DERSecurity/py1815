"""An independent outstation built on opendnp3, for testing the py1815 master.

Runs under Python 3.10 with ``dnp3-python``, which wraps opendnp3, a C++ DNP3
stack that this project did not write. The py1815 master reads and commands it
in the interoperability job (``interop/master_check.py``). Agreement with this
outstation is evidence about the master, because the two share no code.

The points served and the control rules are the fixture in ``FIXTURE`` below.
``master_check.py`` and ``interop/rust-outstation`` carry the same fixture.

Every control and time write received is printed, one line each, in the format
``master_check.py`` reads from this process's log:

    control select bo 0 latch_on
    control operate ao 1 250
    time written 1700000000000

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import queue
import sys
import threading
import time

from pydnp3 import asiodnp3, asiopal, opendnp3, openpal

# ---- The fixture. Must match interop/master_check.py and interop/rust-outstation.

#: Binary inputs 0 to 4.
BINARY_INPUTS = [True, False, True, False, True]
#: Analog inputs 0 to 4, served as 32-bit integers. Index 3 is offline.
ANALOG_INPUTS = [10, -20, 30, 40, 50]
ANALOG_OFFLINE_INDEX = 3
#: Analog inputs 5 and up hold their own index, to make the integrity poll
#: larger than one fragment.
ANALOG_COUNT = 600
#: Counters 0 and 1.
COUNTERS = [100, 200]
#: Binary and analog outputs 0 to 2 exist. Any other index is NOT_SUPPORTED.
OUTPUT_COUNT = 3
#: Analog output 2 refuses a value above this with OUT_OF_RANGE.
ANALOG_OUTPUT_LIMIT_INDEX = 2
ANALOG_OUTPUT_LIMIT = 1000.0
#: An operate on binary output 0 is mirrored to this binary input, and an
#: operate on analog output 0 to this analog input, so each raises an event.
MIRROR_BINARY_INPUT = 1
MIRROR_ANALOG_INPUT = 1

ONLINE = 0x01
COMM_LOST = 0x04
STATE = 0x80

_CODE_NAMES = {
    opendnp3.ControlCode.LATCH_ON: "latch_on",
    opendnp3.ControlCode.LATCH_OFF: "latch_off",
    opendnp3.ControlCode.PULSE_ON: "pulse_on",
    opendnp3.ControlCode.PULSE_OFF: "pulse_off",
    opendnp3.ControlCode.CLOSE_PULSE_ON: "close",
    opendnp3.ControlCode.TRIP_PULSE_ON: "trip",
}


def say(message: str) -> None:
    """Print one line and flush, so the log is complete if the job is cancelled."""
    print(message, flush=True)


def number(value: float) -> str:
    """Format a control value the way every outstation in this suite logs it."""
    return str(int(value)) if float(value).is_integer() else repr(float(value))


class Application(opendnp3.IOutstationApplication):
    """Asks for the time until a master writes it, and records the write."""

    def __init__(self) -> None:
        super().__init__()
        self.need_time = True

    def SupportsWriteAbsoluteTime(self) -> bool:
        return True

    def WriteAbsoluteTime(self, timestamp: openpal.UTCTimestamp) -> bool:
        say(f"time written {timestamp.msSinceEpoch}")
        self.need_time = False
        return True

    def GetApplicationIIN(self) -> opendnp3.ApplicationIIN:
        indications = opendnp3.ApplicationIIN()
        indications.needTime = self.need_time
        return indications


class Commands(opendnp3.ICommandHandler):
    """Applies the fixture's control rules and logs every control received."""

    #: Database updates waiting to be applied, in the order the controls arrived.
    updates: queue.Queue = queue.Queue()

    def Start(self) -> None:
        pass

    def End(self) -> None:
        pass

    def _check(self, command: object, index: int) -> opendnp3.CommandStatus:
        if index >= OUTPUT_COUNT:
            return opendnp3.CommandStatus.NOT_SUPPORTED
        if isinstance(command, opendnp3.ControlRelayOutputBlock):
            if command.functionCode not in _CODE_NAMES:
                return opendnp3.CommandStatus.NOT_SUPPORTED
            return opendnp3.CommandStatus.SUCCESS
        if index == ANALOG_OUTPUT_LIMIT_INDEX and command.value > ANALOG_OUTPUT_LIMIT:
            return opendnp3.CommandStatus.OUT_OF_RANGE
        return opendnp3.CommandStatus.SUCCESS

    @staticmethod
    def _describe(command: object, index: int) -> str:
        if isinstance(command, opendnp3.ControlRelayOutputBlock):
            return f"bo {index} {_CODE_NAMES.get(command.functionCode, 'other')}"
        return f"ao {index} {number(command.value)}"

    def Select(self, command: object, index: int) -> opendnp3.CommandStatus:
        status = self._check(command, index)
        say(f"control select {self._describe(command, index)}")
        return status

    def Operate(self, command: object, index: int, op_type: object) -> opendnp3.CommandStatus:
        status = self._check(command, index)
        say(f"control operate {self._describe(command, index)}")
        if status == opendnp3.CommandStatus.SUCCESS:
            self._apply(command, index)
        return status

    def _apply(self, command: object, index: int) -> None:
        """Update the output's status, and the input that mirrors output 0."""
        builder = asiodnp3.UpdateBuilder()
        if isinstance(command, opendnp3.ControlRelayOutputBlock):
            on = command.functionCode in (
                opendnp3.ControlCode.LATCH_ON,
                opendnp3.ControlCode.PULSE_ON,
                opendnp3.ControlCode.CLOSE_PULSE_ON,
            )
            builder.Update(opendnp3.BinaryOutputStatus(on), index, opendnp3.EventMode.Suppress)
            if index == 0:
                builder.Update(opendnp3.Binary(on), MIRROR_BINARY_INPUT, opendnp3.EventMode.Force)
        else:
            value = float(command.value)
            builder.Update(opendnp3.AnalogOutputStatus(value), index, opendnp3.EventMode.Suppress)
            if index == 0:
                builder.Update(
                    opendnp3.Analog(value), MIRROR_ANALOG_INPUT, opendnp3.EventMode.Force
                )
        # This callback runs inside the stack, which must not be re-entered
        # from here, so the update is queued. One worker applies the queue in
        # order: a thread per update could apply an older value last.
        Commands.updates.put(builder.Build())


def apply_updates(outstation: object) -> None:
    """Apply queued database updates one at a time, in the order they were queued."""
    while True:
        outstation.Apply(Commands.updates.get())


def configure(port: int, outstation_address: int, master_address: int) -> object:
    """Build the stack configuration: sizes, variations, classes and addresses."""
    sizes = opendnp3.DatabaseSizes(
        numBinary=len(BINARY_INPUTS),
        numDoubleBinary=0,
        numAnalog=ANALOG_COUNT,
        numCounter=len(COUNTERS),
        numFrozenCounter=0,
        numBinaryOutputStatus=OUTPUT_COUNT,
        numAnalogOutputStatus=OUTPUT_COUNT,
        numTimeAndInterval=0,
    )
    stack = asiodnp3.OutstationStackConfig(dbSizes=sizes)
    stack.outstation.eventBufferConfig = opendnp3.EventBufferConfig().AllTypes(100)
    stack.outstation.params.allowUnsolicited = True
    stack.link.LocalAddr = outstation_address
    stack.link.RemoteAddr = master_address
    stack.link.KeepAliveTimeout = openpal.TimeDuration().Max()

    database = stack.dbConfig
    for index in range(len(BINARY_INPUTS)):
        database.binary[index].clazz = opendnp3.PointClass.Class1
        database.binary[index].svariation = opendnp3.StaticBinaryVariation.Group1Var2
        database.binary[index].evariation = opendnp3.EventBinaryVariation.Group2Var1
    for index in range(ANALOG_COUNT):
        database.analog[index].clazz = opendnp3.PointClass.Class2
        database.analog[index].svariation = opendnp3.StaticAnalogVariation.Group30Var1
        database.analog[index].evariation = opendnp3.EventAnalogVariation.Group32Var1
    for index in range(len(COUNTERS)):
        database.counter[index].clazz = opendnp3.PointClass.Class3
        database.counter[index].svariation = opendnp3.StaticCounterVariation.Group20Var1
    for index in range(OUTPUT_COUNT):
        database.boStatus[index].svariation = opendnp3.StaticBinaryOutputStatusVariation.Group10Var2
        database.aoStatus[index].svariation = opendnp3.StaticAnalogOutputStatusVariation.Group40Var1
    return stack


def load(outstation: object) -> None:
    """Set every point to its fixture value, without raising events."""
    quiet = opendnp3.EventMode.Suppress
    builder = asiodnp3.UpdateBuilder()
    for index, value in enumerate(BINARY_INPUTS):
        builder.Update(opendnp3.Binary(value), index, quiet)
    for index in range(ANALOG_COUNT):
        value = float(ANALOG_INPUTS[index] if index < len(ANALOG_INPUTS) else index)
        flags = COMM_LOST if index == ANALOG_OFFLINE_INDEX else ONLINE
        builder.Update(opendnp3.Analog(value, opendnp3.Flags(flags)), index, quiet)
    for index, count in enumerate(COUNTERS):
        builder.Update(opendnp3.Counter(count), index, quiet)
    for index in range(OUTPUT_COUNT):
        builder.Update(opendnp3.BinaryOutputStatus(False), index, quiet)
        builder.Update(opendnp3.AnalogOutputStatus(0.0), index, quiet)
    outstation.Apply(builder.Build())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--outstation-address", type=int, default=1024)
    parser.add_argument("--master-address", type=int, default=1)
    args = parser.parse_args()

    manager = asiodnp3.DNP3Manager(1, asiodnp3.ConsoleLogger().Create())
    channel = manager.AddTCPServer(
        id="server",
        levels=opendnp3.levels.NORMAL,
        retry=asiopal.ChannelRetry().Default(),
        endpoint=args.host,
        port=args.port,
        listener=asiodnp3.PrintingChannelListener().Create(),
    )
    application = Application()
    commands = Commands()
    outstation = channel.AddOutstation(
        id="outstation",
        commandHandler=commands,
        application=application,
        config=configure(args.port, args.outstation_address, args.master_address),
    )
    threading.Thread(target=apply_updates, args=(outstation,), daemon=True).start()
    load(outstation)
    outstation.Enable()
    say(f"outstation listening on {args.host}:{args.port}")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
