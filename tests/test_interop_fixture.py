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
    session = Session(
        outstation.FixedProvider(), outstation_address=OUTSTATION, master_address=MASTER
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
