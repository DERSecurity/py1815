"""IED certification procedures, section 10: output events, at Subset Level 4.

Section 10 is tested only where the Device Profile claims output events, which
this outstation does at Level 4 (D115). Each output of the device under test
has a status reader, so a test can change an output's flags the way a device
reports a fault. The outputs have no paired input, so their events report in
class 3. Command events (10.3.4 and 10.4.4) are not generated (D116), so those
sections do not apply; ``tests/test_ied_coverage.py`` says so.
"""

from __future__ import annotations

from ied_harness import (
    DIRECT_OPERATE,
    FLAG_ONLINE,
    Dut,
    analog_output,
    classes,
    crob,
)

from py1815.profile.binding import Quality
from py1815.profile.model import Kind

#: COMM_LOST, bit 2 of the flag octet in groups 10, 11, 40 and 42 (IEEE 1815-2012
#: A.6.2 and A.19.1), without ONLINE: what a status reader reporting lost
#: communication produces.
FLAG_COMM_LOST = 0x04


def _dut() -> Dut:
    dut = Dut(level=4, output_status=True)
    dut.master.empty_events()
    return dut


def _events(dut: Dut) -> bytes:
    """Poll classes 1, 2 and 3, confirm the response, and return its body."""
    return b"".join(fragment.body for fragment in dut.master.poll(classes(1, 2, 3)))


def _stamp(dut: Dut) -> str:
    """The device clock now, as the six octets of a DNP3 time."""
    return dut.clock.ms().to_bytes(6, "little").hex(" ")


def _set_quality(dut: Dut, kind: Kind, index: int, quality: Quality) -> None:
    dut.clock.advance(0.01)
    dut.quality[(kind, index)] = quality
    dut.outstation.poll()


class TestBinaryOutputs:
    def test_10_3_2_class_0_carries_every_binary_output_in_variation_2(self):
        dut = _dut()
        objects = dut.master.read(classes(0)).fragment.of(10)
        assert [(o.index, o.variation, o.flags) for o in objects] == [
            (index, 2, FLAG_ONLINE) for index in range(4)
        ]

    def test_10_3_3_a_flag_change_raises_one_event_with_that_flag(self):
        dut = _dut()
        # Steps 4 to 10, for the one flag the device under test changes:
        # g11v2, index 2, COMM_LOST with the state off, then the time.
        _set_quality(dut, Kind.BO, 2, Quality.COMM_LOST)
        assert _events(dut) == bytes.fromhex(f"0B 02 17 01 02 04 {_stamp(dut)}")
        # Step 11: the flag returning to normal is a change too.
        _set_quality(dut, Kind.BO, 2, Quality.GOOD)
        assert _events(dut) == bytes.fromhex(f"0B 02 17 01 02 01 {_stamp(dut)}")
        assert _events(dut) == b""

    def test_10_3_3_a_state_change_raises_one_event_with_the_new_state(self):
        dut = _dut()
        # Steps 12 to 17: a latch on sets the state bit (0x80) beside ONLINE.
        dut.master.request(DIRECT_OPERATE, crob(1, 0x03))
        assert _events(dut) == bytes.fromhex(f"0B 02 17 01 01 81 {_stamp(dut)}")
        assert _events(dut) == b""


class TestAnalogOutputs:
    def test_10_4_2_class_0_carries_every_analog_output(self):
        # The procedure configures 16-bit outputs and expects variation 2. This
        # outstation sends variation 1 at Level 4, which Table 12-49 allows.
        dut = _dut()
        objects = dut.master.read(classes(0)).fragment.of(40)
        assert [(o.index, o.variation, o.flags) for o in objects] == [
            (index, 1, FLAG_ONLINE) for index in range(4)
        ]

    def test_10_4_3_a_flag_change_raises_one_event_with_that_flag(self):
        dut = _dut()
        # Steps 5 to 13: g42v3, index 3, COMM_LOST, the value 0 in 32 bits, the time.
        _set_quality(dut, Kind.AO, 3, Quality.COMM_LOST)
        assert _events(dut) == bytes.fromhex(f"2A 03 17 01 03 04 00 00 00 00 {_stamp(dut)}")
        _set_quality(dut, Kind.AO, 3, Quality.GOOD)
        assert _events(dut) == bytes.fromhex(f"2A 03 17 01 03 01 00 00 00 00 {_stamp(dut)}")
        assert _events(dut) == b""

    def test_10_4_3_a_commanded_value_change_raises_one_event_with_the_value(self):
        dut = _dut()
        # Steps 14 to 21, and 27 to 34: every change of the commanded value is
        # an event, since output events have no deadband (D115). 40 and 51 are
        # 0x28 and 0x33.
        for value, octet in ((40, "28"), (51, "33")):
            dut.master.request(DIRECT_OPERATE, analog_output(0, value))
            assert _events(dut) == bytes.fromhex(
                f"2A 03 17 01 00 01 {octet} 00 00 00 {_stamp(dut)}"
            )
        assert _events(dut) == b""
