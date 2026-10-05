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


class Reporting(Device):
    """A device that says for itself whether the function is enabled."""

    def __init__(self, enabled: bool, **options) -> None:
        self.enabled = enabled
        self.reachable = True
        self.quality = Quality.GOOD
        binding = Binding()
        binding.output(Kind.BO, ENABLE, self._set, status=self._status)
        binding.read(Kind.AI, COMPUTED, lambda: Reading(42.0, self.quality))
        binding.read(Kind.BI, SWITCH_STATE, lambda: True)
        self.outstation = DerOutstation(
            load.resolve(_tables(), Composition()), binding, strict=False, **options
        )
        self.outstation.poll()
        self.master = TestMaster(self.outstation.session(need_time=False))

    def _set(self, value: bool) -> None:
        self.enabled = value

    def _status(self) -> bool:
        if not self.reachable:
            raise OSError("unreachable")
        return self.enabled


class TestWhenTheDeviceSaysWhetherItIsEnabled:
    """Whether a function is enabled is what its enable output stands at, and
    that is asked the way the output's status and its mirror ask it (D65)."""

    def test_a_function_already_enabled_is_in_effect_before_anything_is_written(self):
        """As after the outstation restarts beside a device that kept running."""
        device = Reporting(enabled=True)
        assert device.read(30)[COMPUTED] == (42, AnalogQuality.ONLINE)
        assert device.read(1)[SWITCH_STATE] == (True, BinaryQuality.ONLINE)

    def test_and_one_the_device_holds_disabled_is_not(self):
        assert Reporting(enabled=False).read(30)[COMPUTED] == (42, 0)

    def test_a_function_the_device_turns_off_by_itself_goes_out_of_effect(self):
        """The master's own enable was accepted, and is no longer what is in force."""
        device = Reporting(enabled=False)
        device.enable(True)
        assert device.read(30)[COMPUTED] == (42, AnalogQuality.ONLINE)
        device.enabled = False
        assert device.read(30)[COMPUTED] == (42, 0)

    def test_which_a_master_following_events_is_told(self):
        device = Reporting(enabled=True)
        device.enabled = False
        device.outstation.poll()
        events = device.outstation.events
        assert {e.index: e.point.flags for e in events.peek_kind(AnalogEvent)} == {COMPUTED: 0}

    def test_the_status_the_mirror_and_the_inputs_say_the_same_thing(self):
        for enabled in (True, False):
            device = Reporting(enabled=enabled)
            (status,) = device.master.read(header(10, 2)).fragment.objects
            assert bool(status.state) is enabled
            assert device.read(1)[STATUS] == (enabled, BinaryQuality.ONLINE)
            assert bool(device.read(30)[COMPUTED][1] & AnalogQuality.ONLINE) is enabled

    def test_a_read_only_outstation_follows_what_another_interface_enabled(self):
        """It accepts no write, so the last one it accepted could never say."""
        device = Reporting(enabled=True, read_only=True)
        assert device.read(30)[COMPUTED] == (42, AnalogQuality.ONLINE)
        device.enabled = False
        assert device.read(30)[COMPUTED] == (42, 0)

    def test_a_change_of_role_does_not_put_an_enabled_function_out_of_effect(self):
        device = Reporting(enabled=False)
        device.enable(True)
        device.outstation.read_only = True
        assert device.read(30)[COMPUTED] == (42, AnalogQuality.ONLINE)
        device.outstation.read_only = False
        assert device.read(30)[COMPUTED] == (42, AnalogQuality.ONLINE)

    def test_a_status_that_cannot_be_read_is_not_taken_as_enabled(self):
        """Not knowing is not grounds to tell a master a setting is in force."""
        device = Reporting(enabled=True)
        device.reachable = False
        assert device.read(30)[COMPUTED] == (42, 0)

    def test_without_a_status_reader_the_last_accepted_write_still_decides(self):
        """The control: an output that cannot be asked is taken at the master's word."""
        device = Device()
        assert device.read(30)[COMPUTED] == (42, 0)
        device.enable(True)
        assert device.read(30)[COMPUTED] == (42, AnalogQuality.ONLINE)


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
