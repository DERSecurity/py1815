"""What the interoperability job serves, pinned where CI can see it.

The job's master reads five numbers and checks them. It cannot check anything
else: it stores point values as bare scalars and discards the quality octet, so
the object header, the indication bits and the offline point's flags go
unverified there. Those were checked once by hand against a running outstation,
which is a thing that was true on one machine on one afternoon.

This pins them instead, against the same fixture the job runs, so a change that
broke them would fail the suite rather than pass an interoperability run that
was never looking.
"""

from __future__ import annotations

import importlib.util
import pathlib
import struct

import pytest

from py1815 import link
from py1815.application import FunctionCode, IINBit, QualifierCode
from py1815.objects import AnalogQuality
from py1815.session import Session

_FIXTURE = pathlib.Path(__file__).resolve().parents[1] / "interop" / "outstation.py"

OUTSTATION = 1024
MASTER = 1


def _fixture():
    """Load ``interop/outstation.py``, which is a script rather than a package."""
    spec = importlib.util.spec_from_file_location("interop_outstation", _FIXTURE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def outstation():
    return _fixture()


@pytest.fixture
def response(outstation) -> bytes:
    """The application fragment a class-0 read gets back from the fixture."""
    controls = outstation.FixedControls()
    session = Session(
        outstation.FixedProvider(controls),
        control_provider=controls,
        outstation_address=OUTSTATION,
        master_address=MASTER,
    )
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    request = link.build(
        control,
        destination=OUTSTATION,
        source=MASTER,
        payload=b"\xc0" + bytes([0xC0, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS]),
    )
    frames = link.FrameReader().feed(session.receive(request))
    return frames[0].payload[1:]


class TestTheServedFixture:
    def test_the_points_are_derived_from_one_list(self, outstation):
        """Two lists where only one is read is the arrangement that drifts."""
        assert [point.value for point in outstation.POINTS] == outstation.EXPECTED

    def test_exactly_one_point_is_offline(self, outstation):
        offline = [
            index
            for index, point in enumerate(outstation.POINTS)
            if not point.flags & AnalogQuality.ONLINE
        ]

        assert offline == [outstation.OFFLINE_INDEX]

    def test_the_response_is_a_response(self, response):
        assert response[1] == FunctionCode.RESPONSE

    def test_the_restart_indication_is_set_until_a_master_clears_it(self, response):
        """Checked by hand once against a live outstation; checked here every run."""
        assert response[2] & IINBit.DEVICE_RESTART

    def test_the_object_header_covers_the_whole_range(self, response, outstation):
        group, variation, qualifier, start, stop = response[4:9]

        assert (group, variation) == (30, 1)
        assert qualifier == QualifierCode.UINT8_START_STOP
        assert (start, stop) == (0, len(outstation.EXPECTED) - 1)

    def test_every_value_is_on_the_wire_in_order(self, response, outstation):
        objects = response[9:]
        values = [
            struct.unpack("<i", objects[index * 5 + 1 : index * 5 + 5])[0]
            for index in range(len(outstation.EXPECTED))
        ]

        assert values == outstation.EXPECTED

    def test_the_offline_point_carries_comm_lost_and_not_online(self, response, outstation):
        """The assertion the interoperability job structurally cannot make: its
        master discards the quality octet before any caller sees it."""
        objects = response[9:]
        flags = objects[outstation.OFFLINE_INDEX * 5]

        assert flags & AnalogQuality.COMM_LOST
        assert not flags & AnalogQuality.ONLINE

    def test_every_other_point_is_online(self, response, outstation):
        objects = response[9:]

        for index in range(len(outstation.EXPECTED)):
            if index == outstation.OFFLINE_INDEX:
                continue
            assert objects[index * 5] & AnalogQuality.ONLINE


class TestTheFixtureAcceptsControls:
    """The half the C++ master cannot show and the Rust one now does.

    Pinned here as well, because the interoperability job proves these against a
    running outstation and this proves them without a socket -- the same
    argument the module docstring makes about the quality octet.
    """

    def test_a_point_it_owns_is_operated_and_remembered(self, outstation):
        from py1815.control import CommandStatus, ControlRelayOutputBlock, OperationType
        from py1815.session import Control

        controls = outstation.FixedControls()
        latch_on = Control(
            block=0,
            group=12,
            variation=1,
            index=outstation.CONTROLLABLE_BINARY[0],
            raw=b"",
            command=ControlRelayOutputBlock.build(OperationType.LATCH_ON),
        )

        assert controls.operate([latch_on]) == [CommandStatus.SUCCESS]
        assert controls.binary[outstation.CONTROLLABLE_BINARY[0]] is True

    def test_a_point_it_does_not_own_is_refused_per_object(self, outstation):
        """The two answers arrive in one request, which is the case a
        fragment-level refusal cannot demonstrate."""
        from py1815.control import CommandStatus, ControlRelayOutputBlock, OperationType
        from py1815.session import Control

        controls = outstation.FixedControls()

        def latch(index):
            return Control(
                block=0,
                group=12,
                variation=1,
                index=index,
                raw=b"",
                command=ControlRelayOutputBlock.build(OperationType.LATCH_ON),
            )

        statuses = controls.operate(
            [latch(outstation.CONTROLLABLE_BINARY[0]), latch(outstation.UNCONTROLLABLE_BINARY)]
        )

        assert statuses == [CommandStatus.SUCCESS, CommandStatus.NOT_SUPPORTED]

    def test_a_refused_point_is_not_applied(self, outstation):
        from py1815.control import ControlRelayOutputBlock, OperationType
        from py1815.session import Control

        controls = outstation.FixedControls()
        controls.operate(
            [
                Control(
                    block=0,
                    group=12,
                    variation=1,
                    index=outstation.UNCONTROLLABLE_BINARY,
                    raw=b"",
                    command=ControlRelayOutputBlock.build(OperationType.LATCH_ON),
                )
            ]
        )

        assert outstation.UNCONTROLLABLE_BINARY not in controls.binary

    def test_the_readback_reflects_what_was_commanded(self, outstation):
        """A constant would look identical if the control had been dropped."""
        from py1815.control import (
            GROUP_BINARY_OUTPUT_STATUS,
            BinaryQuality,
            ControlRelayOutputBlock,
            OperationType,
        )
        from py1815.session import Control

        controls = outstation.FixedControls()
        before = controls.status_objects(GROUP_BINARY_OUTPUT_STATUS)
        controls.operate(
            [
                Control(
                    block=0,
                    group=12,
                    variation=1,
                    index=outstation.CONTROLLABLE_BINARY[0],
                    raw=b"",
                    command=ControlRelayOutputBlock.build(OperationType.LATCH_ON),
                )
            ]
        )
        after = controls.status_objects(GROUP_BINARY_OUTPUT_STATUS)

        assert not before[0] & BinaryQuality.STATE
        assert after[0] & BinaryQuality.STATE
