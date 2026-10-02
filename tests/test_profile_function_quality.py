"""The inputs of a function that is disabled are sent without the ONLINE flag.

IEEE 1815.2 clause 6.1.1 has an outstation mark the inputs of a disabled
function as invalid. These tests build a small function out of synthetic
tables and read its points as a master would.
"""

from __future__ import annotations

import pytest
from ied_harness import DIRECT_OPERATE, Q_INDEX_8, TestMaster, crob, header
from profile_fixtures import analog, document, row

from py1815.control import CommandStatus
from py1815.events import AnalogEvent, BinaryEvent
from py1815.objects import AnalogQuality, BinaryQuality
from py1815.profile import load
from py1815.profile.binding import Binding, Quality, Reading
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation

ENABLE, STATUS, SUPPORTS = 0, 0, 1
COMPUTED, READBACK, ELSEWHERE, OTHER_HEADING = 0, 1, 2, 3
SWITCH_STATE = 2


def _tables() -> dict:
    return document(
        {
            "BO": [row("Enable Gadget", ENABLE, purpose="Gadget", associated=f"BI{STATUS}")],
            "BI": [
                row("Gadget enabled", STATUS, event_class=1, purpose="Gadget", associated="BO0"),
                row("Supports Gadget", SUPPORTS, event_class=0, purpose="Gadget"),
                row("Gadget is holding", SWITCH_STATE, event_class=1, purpose="gadget"),
            ],
            "AO": [analog("Gadget target", 0, purpose="Gadget", associated=f"AI{READBACK}")],
            "AI": [
                analog("Gadget output", COMPUTED, event_class=2, purpose="GADGET"),
                analog(
                    "Gadget target", READBACK, event_class=2, purpose="Gadget", associated="AO0"
                ),
                analog("Something else", ELSEWHERE, event_class=2, purpose="Widget"),
                analog(
                    "Gadget, under another heading",
                    OTHER_HEADING,
                    event_class=2,
                    purpose="Gadget",
                    section="Elsewhere",
                ),
            ],
        }
    )


class Device:
    def __init__(self, **options) -> None:
        self.quality = Quality.GOOD
        binding = Binding()
        binding.output(Kind.BO, ENABLE, initial=False)
        binding.output(Kind.AO, 0, initial=5.0)
        binding.read(Kind.BI, SWITCH_STATE, lambda: True)
        binding.read(Kind.AI, COMPUTED, lambda: Reading(42.0, self.quality))
        binding.read(Kind.AI, ELSEWHERE, lambda: 7.0)
        binding.read(Kind.AI, OTHER_HEADING, lambda: 8.0)
        self.outstation = DerOutstation(
            load.resolve(_tables(), Composition()), binding, strict=False, **options
        )
        self.outstation.poll()
        self.master = TestMaster(self.outstation.session(need_time=False))

    def enable(self, on: bool) -> None:
        body = crob(ENABLE, 0x03 if on else 0x04, qualifier=Q_INDEX_8)
        (echo,) = self.master.request(DIRECT_OPERATE, body).fragment.objects
        assert echo.status == CommandStatus.SUCCESS

    def read(self, group: int) -> dict[int, tuple[float, int]]:
        """Every point of one kind, as its value and its quality flags."""
        fragment = self.master.read(header(group, 2 if group == 1 else 1)).fragment
        assert not fragment.is_error
        if group == 1:
            return {o.index: (o.state, o.flags & 0x7F) for o in fragment.objects}
        return {o.index: (o.value, o.flags) for o in fragment.objects}


class TestWhileTheFunctionIsDisabled:
    def test_its_inputs_carry_their_values_and_no_flag(self):
        device = Device()
        analogs, binaries = device.read(30), device.read(1)
        assert analogs[COMPUTED] == (42, 0)
        assert analogs[READBACK] == (5, 0)
        assert binaries[SWITCH_STATE] == (True, 0)

    def test_the_points_that_describe_the_function_itself_stay_online(self):
        """Whether it is supported, and whether it is enabled, are true either way."""
        binaries = Device().read(1)
        assert binaries[SUPPORTS] == (True, BinaryQuality.ONLINE)
        assert binaries[STATUS] == (False, BinaryQuality.ONLINE)

    def test_points_of_another_purpose_or_under_another_heading_are_untouched(self):
        analogs = Device().read(30)
        assert analogs[ELSEWHERE] == (7, AnalogQuality.ONLINE)
        assert analogs[OTHER_HEADING] == (8, AnalogQuality.ONLINE)

    def test_a_worse_quality_is_not_replaced(self):
        """A source that cannot be reached is still reported as one that cannot."""
        device = Device()
        device.quality = Quality.COMM_LOST
        assert device.read(30)[COMPUTED][1] == AnalogQuality.COMM_LOST


class TestOnceItIsEnabled:
    def test_its_inputs_are_online(self):
        device = Device()
        device.enable(True)
        analogs, binaries = device.read(30), device.read(1)
        assert analogs[COMPUTED] == (42, AnalogQuality.ONLINE)
        assert analogs[READBACK] == (5, AnalogQuality.ONLINE)
        assert binaries[SWITCH_STATE] == (True, BinaryQuality.ONLINE)
        assert binaries[STATUS] == (True, BinaryQuality.ONLINE)

    def test_and_go_back_when_it_is_disabled_again(self):
        device = Device()
        device.enable(True)
        device.enable(False)
        assert device.read(30)[COMPUTED] == (42, 0)

    def test_the_change_of_quality_is_reported_as_events(self):
        """A master following events learns the values came into effect without polling."""
        device = Device()
        device.enable(True)
        device.outstation.poll()
        events = device.outstation.events
        analog_events = {e.index: e.point.flags for e in events.peek_kind(AnalogEvent)}
        binary_events = {e.index: e.point.flags for e in events.peek_kind(BinaryEvent)}
        assert analog_events[COMPUTED] == AnalogQuality.ONLINE
        assert analog_events[READBACK] == AnalogQuality.ONLINE
        assert binary_events[SWITCH_STATE] & BinaryQuality.ONLINE
        assert ELSEWHERE not in analog_events


class TestTurnedOff:
    def test_every_input_is_online_whatever_the_function_is_doing(self):
        device = Device(disabled_offline=False)
        analogs, binaries = device.read(30), device.read(1)
        assert analogs[COMPUTED] == (42, AnalogQuality.ONLINE)
        assert analogs[READBACK] == (5, AnalogQuality.ONLINE)
        assert binaries[SWITCH_STATE] == (True, BinaryQuality.ONLINE)


class TestAFunctionThatIsNotImplemented:
    def test_nothing_is_gated_by_an_enable_output_that_is_not_bound(self):
        """Its settings are bound by nobody and not served; what a caller does bind is online."""
        binding = Binding()
        binding.read(Kind.AI, COMPUTED, lambda: 42.0)
        outstation = DerOutstation(load.resolve(_tables(), Composition()), binding, strict=False)
        master = TestMaster(outstation.session(need_time=False))
        objects = master.read(header(30, 1)).fragment.objects
        assert [(o.index, o.flags) for o in objects] == [(COMPUTED, AnalogQuality.ONLINE)]


@pytest.mark.parametrize("quality", list(Quality))
def test_every_quality_has_flags(quality):
    """A quality with no flags to send would fail on the first read that met it."""
    device = Device()
    device.enable(True)
    device.quality = quality
    assert isinstance(device.read(30)[COMPUTED][1], int)
