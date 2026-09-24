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


def _latch(outstation, index, on=True):
    """One CROB against *index*, as it would reach a provider."""
    from py1815.control import ControlRelayOutputBlock, OperationType
    from py1815.session import Control

    return Control(
        function=FunctionCode.DIRECT_OPERATE,
        block=0,
        group=12,
        variation=1,
        index=index,
        raw=b"",
        command=ControlRelayOutputBlock.build(
            OperationType.LATCH_ON if on else OperationType.LATCH_OFF
        ),
    )


class TestTheFixtureAcceptsControls:
    """The half the C++ master cannot show and the Rust one now does.

    Pinned here as well, because the interoperability job proves these against a
    running outstation and this proves them without a socket -- the same
    argument the module docstring makes about the quality octet.
    """

    def test_a_point_it_owns_is_operated_and_remembered(self, outstation):
        from py1815.control import CommandStatus

        controls = outstation.FixedControls()
        owned = outstation.CONTROLLABLE_BINARY[0]

        assert controls.operate([_latch(outstation, owned)]) == [CommandStatus.SUCCESS]
        assert controls.binary[owned] is True

    def test_a_point_it_does_not_own_is_refused_per_object(self, outstation):
        """Both answers arrive in one request, which is the case a
        fragment-level refusal cannot demonstrate."""
        from py1815.control import CommandStatus

        controls = outstation.FixedControls()

        statuses = controls.operate(
            [
                _latch(outstation, outstation.CONTROLLABLE_BINARY[0]),
                _latch(outstation, outstation.UNCONTROLLABLE_BINARY),
            ]
        )

        assert statuses == [CommandStatus.SUCCESS, CommandStatus.NOT_SUPPORTED]

    def test_a_refused_point_is_not_applied(self, outstation):
        controls = outstation.FixedControls()

        controls.operate([_latch(outstation, outstation.UNCONTROLLABLE_BINARY)])

        assert outstation.UNCONTROLLABLE_BINARY not in controls.binary

    def test_the_obsolete_queue_bit_is_a_format_error(self, outstation):
        """Bit 4 was withdrawn by IEEE 1815-2012 and required to be zero. A
        control that sets it is malformed rather than unimplemented, and the
        low nibble still naming LATCH_ON does not make it acceptable."""
        from py1815.control import CommandStatus, ControlRelayOutputBlock
        from py1815.session import Control

        controls = outstation.FixedControls()
        queued = Control(
            function=FunctionCode.DIRECT_OPERATE,
            block=0,
            group=12,
            variation=1,
            index=outstation.CONTROLLABLE_BINARY[0],
            raw=b"",
            command=ControlRelayOutputBlock(control_code=0x13),
        )

        assert controls.operate([queued]) == [CommandStatus.FORMAT_ERROR]
        assert controls.binary[outstation.CONTROLLABLE_BINARY[0]] is False

    def test_the_readback_reflects_what_was_commanded(self, outstation):
        """A constant would look identical if the control had been dropped."""
        from py1815.control import GROUP_BINARY_OUTPUT_STATUS, BinaryQuality

        controls = outstation.FixedControls()
        before = controls.status_objects(GROUP_BINARY_OUTPUT_STATUS)
        controls.operate([_latch(outstation, outstation.CONTROLLABLE_BINARY[0])])
        after = controls.status_objects(GROUP_BINARY_OUTPUT_STATUS)

        # Past the object header, which both carry.
        assert not before[-2] & BinaryQuality.STATE
        assert after[-2] & BinaryQuality.STATE

    def test_a_readback_block_carries_its_object_header(self, outstation):
        """A provider hands the session a response body and the session forwards
        it unchanged, so objects returned bare would have a master reading the
        first status octet as an object group."""
        from py1815.control import GROUP_BINARY_OUTPUT_STATUS

        block = outstation.FixedControls().status_objects(GROUP_BINARY_OUTPUT_STATUS)

        assert block[0] == GROUP_BINARY_OUTPUT_STATUS
        assert block[1] == 2, "variation 2 carries the flags the packed one does not"


class TestAMixedRead:
    """A master that commands a point and reads it back alongside its inputs is
    the ordinary case, not an exotic one. Answering only one of the groups asked
    for drops data without saying so."""

    def test_output_status_and_analog_inputs_both_come_back(self, outstation):
        from py1815.control import GROUP_BINARY_OUTPUT_STATUS
        from py1815.session import Session

        controls = outstation.FixedControls()
        session = Session(
            outstation.FixedProvider(controls),
            control_provider=controls,
            outstation_address=OUTSTATION,
            master_address=MASTER,
        )
        mixed = bytes(
            [
                0xC0,
                FunctionCode.READ,
                GROUP_BINARY_OUTPUT_STATUS,
                2,
                QualifierCode.UINT8_START_STOP,
                0,
                1,
                30,
                1,
                QualifierCode.UINT8_START_STOP,
                0,
                4,
            ]
        )

        body = session._handle_fragment(mixed)[4:]

        assert body[0] == GROUP_BINARY_OUTPUT_STATUS, "the readback leads"
        assert bytes([30, 1]) in body, "and the inputs are still there"

    def test_an_output_only_read_carries_no_inputs(self, outstation):
        from py1815.control import GROUP_BINARY_OUTPUT_STATUS
        from py1815.session import Session

        controls = outstation.FixedControls()
        session = Session(
            outstation.FixedProvider(controls),
            control_provider=controls,
            outstation_address=OUTSTATION,
            master_address=MASTER,
        )
        request = bytes(
            [
                0xC0,
                FunctionCode.READ,
                GROUP_BINARY_OUTPUT_STATUS,
                2,
                QualifierCode.UINT8_START_STOP,
                0,
                1,
            ]
        )

        body = session._handle_fragment(request)[4:]

        assert bytes([30, 1]) not in body
