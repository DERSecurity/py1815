"""The analog and counter variations of subset Level 4, and analog input deadbands.

Each case sends literal octets to a session and compares the response with
octets written out by hand. Level 4 serves what Level 3 refuses: the
floating-point variations, the time-stamped 16-bit counters, and group 34.
"""

from __future__ import annotations

import datetime
import pathlib

import pytest
from profile_fixtures import small, units

from py1815.application import FunctionCode, IIN2Bit
from py1815.decode import PointType, decode_objects
from py1815.events import EventClass
from py1815.objects import AnalogEventVariation
from py1815.profile import device_profile, load
from py1815.profile.binding import Binding
from py1815.profile.device_profile import NAMESPACE
from py1815.profile.model import Kind
from py1815.profile.outstation import DerOutstation
from py1815.session import Session

AI, AO, CTR = Kind.AI, Kind.AO, Kind.CTR

OBJECT_UNKNOWN = IIN2Bit.OBJECT_UNKNOWN
PARAM_ERROR = IIN2Bit.PARAM_ERROR

#: The clock every outstation here runs on: 5000 ms, which is 88 13 00 00 00 00 on the wire.
CLOCK_MS = 5000
TIME_5000 = "88 13 00 00 00 00"


class Plant:
    """Values a test moves. Voltage is scaled by 0.1 in the tables, power is not."""

    def __init__(self) -> None:
        self.power = 1500.0
        self.voltage = 240.0

    def outstation(self, level: int | None, **options) -> DerOutstation:
        binding = Binding()
        # Power: a deadband of 5 transmitted units, given with the binding.
        binding.read(AI, 1, lambda: self.power, deadband=5)
        # Voltage: a deadband of 2.0 volts, which is 20 transmitted units.
        binding.read(AI, 2, lambda: self.voltage)
        binding.read(AI, 4, lambda: 7.0)
        binding.read(CTR, 0, lambda: 10.0)
        binding.read(CTR, 1, lambda: 20.0)
        binding.output(AO, 0, initial=12.5)
        point_map = load.resolve(small(), units(0))
        return DerOutstation(
            point_map,
            binding,
            strict=False,
            clock_ms=lambda: CLOCK_MS,
            level=level,
            event_policy={"points": {"AI2": {"deadband": 2.0}}},
            **options,
        )


class Master:
    """Sends application fragments to a session, one sequence number after another."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self.sequence = 0

    def send(self, function: int, body: str) -> bytes:
        fragment = bytes([0xC0 | self.sequence, function]) + bytes.fromhex(body)
        self.sequence = (self.sequence + 1) % 16
        return self.session._handle_fragment(fragment)

    def read(self, body: str) -> bytes:
        return self.send(FunctionCode.READ, body)

    def write(self, body: str) -> bytes:
        return self.send(FunctionCode.WRITE, body)


def _body(response: bytes) -> str:
    """The objects of a response, after the four octets of application header."""
    return response[4:].hex(" ")


def _iin2(response: bytes) -> int:
    return response[3]


def _master(level: int | None, plant: Plant | None = None, **options) -> tuple[Master, Plant]:
    plant = plant or Plant()
    outstation = plant.outstation(level, **options)
    return Master(outstation.session()), plant


def _with_event(level: int | None, **session_options) -> tuple[Master, DerOutstation]:
    """An outstation whose voltage has moved from 240.0 to 244.07, which is one event."""
    plant = Plant()
    outstation = plant.outstation(level)
    outstation.poll()
    plant.voltage = 244.07
    assert outstation.poll() == 1
    return Master(outstation.session(**session_options)), outstation


class TestFloatingPointStaticObjects:
    def test_level_4_serves_g30v5_unscaled(self):
        master, _ = _master(4)
        # Group 30 variation 5, start-stop 1..2: power 1500.0 and voltage 240.0,
        # each a flag octet then a little-endian float. The voltage's multiplier
        # of 0.1 is not applied, where g30v1 carries it as 2400.
        assert _body(master.read("1E 05 00 01 02")) == (
            "1e 05 00 01 02 01 00 80 bb 44 01 00 00 70 43"
        )
        assert _body(master.read("1E 01 00 02 02")) == "1e 01 00 02 02 01 60 09 00 00"

    def test_level_4_serves_g30v5_by_index_and_with_all_objects(self):
        master, _ = _master(4)
        assert _body(master.read("1E 05 17 01 02")) == "1e 05 17 01 02 01 00 00 70 43"
        # Indices 0 to 4 in one range: the version the tables fix, 2.5, which g30v1
        # carries as 25, then power, voltage, the setpoint readback and 7.0.
        assert _body(master.read("1E 05 06")).startswith(
            "1e 05 00 00 04 01 00 00 20 40 01 00 80 bb 44 01 00 00 70 43"
        )

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_g30v5_is_an_unknown_object(self, level):
        master, _ = _master(level)
        response = master.read("1E 05 00 01 02")
        assert _iin2(response) & OBJECT_UNKNOWN
        assert len(response) == 4

    def test_level_4_serves_g40v3_unscaled(self):
        master, _ = _master(4)
        # The setpoint was initialized to 12.5, which is 125 at its multiplier of 0.1.
        assert _body(master.read("28 03 00 00 00")) == "28 03 00 00 00 01 00 00 48 41"
        assert _body(master.read("28 01 00 00 00")) == "28 01 00 00 00 01 7d 00 00 00"

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_g40v3_is_an_unknown_object(self, level):
        master, _ = _master(level)
        assert _iin2(master.read("28 03 00 00 00")) & OBJECT_UNKNOWN

    @pytest.mark.parametrize("level", [3, 4])
    def test_variation_0_and_class_0_stay_integer(self, level):
        master, _ = _master(level)
        assert _body(master.read("1E 00 00 02 02")) == "1e 01 00 02 02 01 60 09 00 00"
        decoded = decode_objects(master.read("3C 01 06")[4:])
        assert decoded.complete
        assert {each.variation for each in decoded.objects if each.group == 30} == {1}

    def test_a_value_with_no_number_is_flagged_in_a_float_too(self):
        plant = Plant()
        plant.power = float("nan")
        master, _ = _master(4, plant)
        # Zero, with ONLINE clear and REFERENCE_ERR (0x40) set.
        assert _body(master.read("1E 05 00 01 01")) == "1e 05 00 01 01 40 00 00 00 00"


class TestFloatingPointEvents:
    def test_a_class_poll_can_report_floats_with_time_at_level_4(self):
        master, _ = _with_event(4, analog_event_variation=AnalogEventVariation.FLOAT32_WITH_TIME)
        # Index 2, flag, 244.07 as a float and the time. The integer form of this
        # change, 2441, would round the figure to 244.1.
        assert _body(master.read("3C 03 06")) == (f"20 07 17 01 02 01 ec 11 74 43 {TIME_5000}")

    def test_a_class_poll_can_report_floats_without_time_at_level_4(self):
        master, _ = _with_event(4, analog_event_variation=AnalogEventVariation.FLOAT32)
        assert _body(master.read("3C 03 06")) == "20 05 17 01 02 01 ec 11 74 43"

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_a_session_refuses_a_floating_point_event_variation(self, level):
        outstation = Plant().outstation(level)
        with pytest.raises(ValueError, match="floating-point"):
            outstation.session(analog_event_variation=AnalogEventVariation.FLOAT32)

    @pytest.mark.parametrize(
        ("request_octets", "expected"),
        [
            ("20 05 06", "20 05 17 01 02 01 ec 11 74 43"),
            ("20 07 06", f"20 07 17 01 02 01 ec 11 74 43 {TIME_5000}"),
            ("20 07 07 01", f"20 07 17 01 02 01 ec 11 74 43 {TIME_5000}"),
        ],
    )
    def test_level_4_serves_g32v5_and_g32v7_by_group(self, request_octets, expected):
        master, _ = _with_event(4)
        assert _body(master.read(request_octets)) == expected

    @pytest.mark.parametrize("request_octets", ["20 05 06", "20 07 06"])
    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_g32v5_and_g32v7_are_unknown_objects(self, request_octets, level):
        master, _ = _with_event(level)
        response = master.read(request_octets)
        assert _iin2(response) & OBJECT_UNKNOWN
        assert len(response) == 4

    @pytest.mark.parametrize(
        ("request_octets", "expected"),
        [
            ("20 03 06", f"20 03 17 01 02 01 89 09 00 00 {TIME_5000}"),
            ("20 04 06", f"20 04 17 01 02 01 89 09 {TIME_5000}"),
        ],
    )
    @pytest.mark.parametrize("level", [None, 3, 4])
    def test_the_timed_integer_events_g32v3_and_g32v4_are_answered_at_every_level(
        self, request_octets, expected, level
    ):
        # Level 4's table lists them; this outstation has always answered them,
        # and a lower level does not turn that off (D113).
        master, _ = _with_event(level)
        assert _body(master.read(request_octets)) == expected


class TestTimeStampedFrozenCounters:
    def _frozen(self, level: int) -> Master:
        outstation = Plant().outstation(level)
        outstation.freeze_all()
        return Master(outstation.session())

    def test_level_4_answers_g21v6_in_32_bits_with_time(self):
        master = self._frozen(4)
        # Two frozen counters, 10 and 20, each in group 21 variation 5: flag,
        # 32-bit count and the time of the freeze. 16 bits would wrap a counter
        # that accumulates energy.
        assert _body(master.read("15 06 06")) == (
            f"15 05 00 00 01 01 0a 00 00 00 {TIME_5000} 01 14 00 00 00 {TIME_5000}"
        )
        assert _body(master.read("15 06 00 00 01")).startswith("15 05 00 00 01")

    def test_level_4_answers_g21v6_by_index(self):
        master = self._frozen(4)
        assert _body(master.read("15 06 17 01 01")) == (
            f"15 05 17 01 01 01 14 00 00 00 {TIME_5000}"
        )

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_g21v6_is_an_unknown_object(self, level):
        outstation = Plant().outstation(level)
        outstation.freeze_all()
        response = Master(outstation.session()).read("15 06 06")
        assert _iin2(response) & OBJECT_UNKNOWN
        assert len(response) == 4

    def test_level_4_answers_g23v6_in_32_bits_with_time(self):
        master = self._frozen(4)
        assert _body(master.read("17 06 06")) == (
            f"17 05 17 02 00 01 0a 00 00 00 {TIME_5000} 01 01 14 00 00 00 {TIME_5000}"
        )

    def test_level_4_answers_g23v6_with_a_count(self):
        master = self._frozen(4)
        assert _body(master.read("17 06 07 01")) == (f"17 05 17 01 00 01 0a 00 00 00 {TIME_5000}")

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_g23v6_is_an_unknown_object(self, level):
        outstation = Plant().outstation(level)
        outstation.freeze_all()
        response = Master(outstation.session()).read("17 06 06")
        assert _iin2(response) & OBJECT_UNKNOWN
        assert len(response) == 4


class TestDeadbandReads:
    @pytest.mark.parametrize(
        ("request_octets", "expected"),
        [
            # Power's 5, and voltage's 2.0 volts, which is 20 at a multiplier of 0.1.
            ("22 01 00 01 02", "22 01 00 01 02 05 00 14 00"),
            ("22 02 00 01 02", "22 02 00 01 02 05 00 00 00 14 00 00 00"),
            # Variation 3 is a float in the units the float variations of the input use:
            # power 5.0, and voltage 2.0 volts.
            ("22 03 00 01 02", "22 03 00 01 02 00 00 a0 40 00 00 00 40"),
            # Variation 0 is answered in 32 bits.
            ("22 00 00 01 02", "22 02 00 01 02 05 00 00 00 14 00 00 00"),
            # A 16-bit range is answered in the narrowest range that holds it.
            ("22 02 01 01 00 02 00", "22 02 00 01 02 05 00 00 00 14 00 00 00"),
            ("22 02 17 02 01 02", "22 02 17 02 01 05 00 00 00 02 14 00 00 00"),
            ("22 01 28 01 00 02 00", "22 01 28 01 00 02 00 14 00"),
        ],
    )
    def test_level_4_reads_each_variation_and_qualifier(self, request_octets, expected):
        master, _ = _master(4)
        assert _body(master.read(request_octets)) == expected

    def test_an_input_with_no_deadband_reads_zero(self):
        master, _ = _master(4)
        assert _body(master.read("22 01 00 04 04")) == "22 01 00 04 04 00 00"

    def test_every_input_reads_with_all_objects(self):
        master, _ = _master(4)
        response = master.read("22 02 06")
        assert not _iin2(response) & (OBJECT_UNKNOWN | PARAM_ERROR)
        decoded = decode_objects(response[4:])
        assert decoded.complete
        by_index = {each.index: each.value for each in decoded.objects}
        assert by_index[1] == 5 and by_index[2] == 20
        assert {0, 1, 2, 4} <= set(by_index)

    def test_a_deadband_past_the_variation_is_the_largest_it_holds(self):
        binding = Binding()
        binding.read(AI, 1, lambda: 0.0, deadband=70000)
        binding.read(AI, 2, lambda: 0.0, deadband=5e9)
        outstation = DerOutstation(load.resolve(small(), units(0)), binding, strict=False, level=4)
        master = Master(outstation.session())
        assert _body(master.read("22 01 17 02 01 02")) == "22 01 17 02 01 ff ff 02 ff ff"
        assert _body(master.read("22 02 17 02 01 02")) == (
            "22 02 17 02 01 70 11 01 00 02 ff ff ff ff"
        )

    def test_a_deadband_is_not_in_class_0(self):
        master, _ = _master(4)
        decoded = decode_objects(master.read("3C 01 06")[4:])
        assert decoded.complete
        assert 34 not in {each.group for each in decoded.objects}

    @pytest.mark.parametrize("level", [None, 2, 3])
    @pytest.mark.parametrize("variation", ["00", "01", "02", "03"])
    def test_below_level_4_group_34_is_an_unknown_object(self, level, variation):
        master, _ = _master(level)
        response = master.read(f"22 {variation} 00 01 02")
        assert _iin2(response) & OBJECT_UNKNOWN
        assert len(response) == 4


class TestDeadbandWrites:
    def test_a_write_is_answered_with_a_null_response(self):
        master, _ = _master(4)
        assert master.write("22 01 00 01 01 0a 00") == bytes.fromhex("c0 81 90 00")

    @pytest.mark.parametrize(
        ("request_octets", "index", "transmitted"),
        [
            # 16-bit, by range.
            ("22 01 00 01 01 0a 00", 1, 10.0),
            ("22 01 01 01 00 01 00 0a 00", 1, 10.0),
            # 32-bit, by index with an 8-bit and a 16-bit prefix.
            ("22 02 17 01 01 64 00 00 00", 1, 100.0),
            ("22 02 28 01 00 01 00 64 00 00 00", 1, 100.0),
            # Single-precision, in the units of the float variations: 7.5 for
            # power, which has no multiplier.
            ("22 03 00 01 01 00 00 f0 40", 1, 7.5),
            # And 5.0 volts for voltage, which is 50 at a multiplier of 0.1.
            ("22 03 00 02 02 00 00 a0 40", 2, 50.0),
        ],
    )
    def test_level_4_accepts_each_variation_and_qualifier(self, request_octets, index, transmitted):
        plant = Plant()
        outstation = plant.outstation(4)
        master = Master(outstation.session())
        response = master.write(request_octets)
        assert response == bytes.fromhex("c0 81 90 00")
        assert outstation.deadband(index) == pytest.approx(transmitted)

    def test_a_write_reads_back_in_every_variation(self):
        master, _ = _master(4)
        master.write("22 02 17 01 02 32 00 00 00")
        # Voltage's deadband is now 50 transmitted units, which is 5.0 volts.
        assert _body(master.read("22 01 00 02 02")) == "22 01 00 02 02 32 00"
        assert _body(master.read("22 02 00 02 02")) == "22 02 00 02 02 32 00 00 00"
        assert _body(master.read("22 03 00 02 02")) == "22 03 00 02 02 00 00 a0 40"

    def test_a_fractional_deadband_reads_back_rounded_in_the_integer_variations(self):
        master, _ = _master(4)
        master.write("22 03 00 01 01 00 00 f0 40")
        assert _body(master.read("22 01 00 01 01")) == "22 01 00 01 01 08 00"
        assert _body(master.read("22 03 00 01 01")) == "22 03 00 01 01 00 00 f0 40"

    def test_one_write_may_hold_several_variations(self):
        plant = Plant()
        outstation = plant.outstation(4)
        master = Master(outstation.session())
        master.write("22 01 00 01 01 0a 00 22 02 17 01 02 1e 00 00 00")
        assert outstation.deadband(1) == 10.0 and outstation.deadband(2) == 30.0

    def test_a_deadband_of_zero_reports_every_change(self):
        plant = Plant()
        outstation = plant.outstation(4)
        outstation.poll()
        Master(outstation.session()).write("22 01 00 01 01 00 00")
        plant.power = 1501.0
        assert outstation.poll() == 1

    @pytest.mark.parametrize(
        "request_octets",
        [
            "22 01 00 09 09 01 00",  # An index that is not an analog input.
            "22 01 00 01 02 01 00",  # A range of two with one object.
            "22 01 00 01 01 01",  # An object cut short.
            "22 03 00 01 01 00 00 80 bf",  # -1.0
            "22 03 00 01 01 00 00 c0 7f",  # NaN
            "22 03 00 01 01 00 00 80 7f",  # Infinity
            "22 02 07 01 64 00 00 00",  # A count with no index to say which point.
            "22 02 17 01 01 64 00 00",  # An object cut short, by index.
        ],
    )
    def test_a_write_that_cannot_be_applied_is_a_parameter_error_and_changes_nothing(
        self, request_octets
    ):
        plant = Plant()
        outstation = plant.outstation(4)
        before = (outstation.deadband(1), outstation.deadband(2))
        response = Master(outstation.session()).write(request_octets)
        assert _iin2(response) == PARAM_ERROR and len(response) == 4
        assert (outstation.deadband(1), outstation.deadband(2)) == before

    def test_a_write_with_one_bad_index_applies_none_of_it(self):
        outstation = Plant().outstation(4)
        before = outstation.deadband(1)
        response = Master(outstation.session()).write("22 01 17 02 01 63 00 09 01 00")
        assert _iin2(response) == PARAM_ERROR
        assert outstation.deadband(1) == before

    def test_group_34_variation_0_cannot_be_written(self):
        outstation = Plant().outstation(4)
        response = Master(outstation.session()).write("22 00 00 01 01")
        assert _iin2(response) & OBJECT_UNKNOWN

    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_below_level_4_a_write_is_an_unknown_object_and_changes_nothing(self, level):
        outstation = Plant().outstation(level)
        before = outstation.deadband(1)
        response = Master(outstation.session()).write("22 01 00 01 01 63 00")
        assert _iin2(response) & OBJECT_UNKNOWN
        assert outstation.deadband(1) == before

    def test_the_time_write_is_unaffected(self):
        outstation = Plant().outstation(4)
        master = Master(outstation.session())
        assert master.write("32 01 07 01 00 10 a5 d4 e8 00") == bytes.fromhex("c0 81 80 00")


class TestAWrittenDeadbandDecidesTheNextEvent:
    def _primed(self, level: int = 4) -> tuple[Plant, DerOutstation, Master]:
        plant = Plant()
        outstation = plant.outstation(level)
        outstation.poll()
        return plant, outstation, Master(outstation.session())

    def test_the_configured_deadband_decides_until_one_is_written(self):
        plant, outstation, _ = self._primed()
        plant.power = 1508.0
        assert outstation.poll() == 1, "8 counts, past the configured 5"

    def test_a_wider_deadband_holds_back_a_change_the_configured_one_reports(self):
        plant, outstation, master = self._primed()
        master.write("22 01 00 01 01 0a 00")
        plant.power = 1508.0
        assert outstation.poll() == 0, "8 counts, inside the written 10"
        plant.power = 1511.0
        assert outstation.poll() == 1, "11 counts, past it"

    def test_a_narrower_deadband_reports_a_change_the_configured_one_holds_back(self):
        plant, outstation, master = self._primed()
        master.write("22 01 00 01 01 02 00")
        plant.power = 1503.0
        assert outstation.poll() == 1, "3 counts, past the written 2"

    def test_the_event_a_written_deadband_lets_through_is_on_the_wire(self):
        plant, outstation, master = self._primed()
        master.write("22 01 00 01 01 0a 00")
        plant.power = 1511.0
        outstation.poll()
        assert _body(master.read("3C 04 06")) == "20 01 17 01 01 01 e7 05 00 00"

    def test_a_deadband_written_in_floats_decides_in_the_units_of_the_float(self):
        plant, outstation, master = self._primed()
        # 10.0 volts at a multiplier of 0.1 is 100 transmitted units.
        master.write("22 03 00 02 02 00 00 20 41")
        plant.voltage = 249.0
        assert outstation.poll() == 0, "90 units"
        plant.voltage = 251.0
        assert outstation.poll() == 1, "110 units"

    def test_a_written_deadband_does_not_outlive_the_outstation(self):
        plant, outstation, master = self._primed()
        master.write("22 01 00 01 01 0a 00")
        assert outstation.deadband(1) == 10.0
        restarted = plant.outstation(4)
        assert restarted.deadband(1) == 5.0, "back to the configured deadband"

    def test_a_written_deadband_is_kept_for_a_point_that_reports_no_events(self):
        _, _, master = self._primed()
        master.write("22 01 00 04 04 03 00")
        assert _body(master.read("22 01 00 04 04")) == "22 01 00 04 04 03 00"


LEVEL_4_ONLY = [
    (30, 5, 1),
    (32, 5, 1),
    (32, 7, 1),
    (40, 3, 1),
    (21, 6, 1),
    (23, 6, 1),
    (34, 0, 1),
    (34, 1, 1),
    (34, 2, 1),
    (34, 3, 1),
    (34, 1, 2),
    (34, 2, 2),
    (34, 3, 2),
]

#: Indices that name served points, for the groups under test.
INDICES = {21: (0, 1), 30: (1, 2), 34: (1, 2), 40: (0, 0)}


class TestTheDeviceProfileTellsWhatIsServed:
    def _rows(self, level: int | None):
        outstation = Plant().outstation(level)
        outstation.freeze_all()
        session = outstation.session()
        table = device_profile.implementation(outstation, session.facts)
        return (
            outstation,
            session,
            {(r.group, r.variation, r.request and r.request[0]) for r in table.rows},
        )

    @pytest.mark.parametrize("row", LEVEL_4_ONLY)
    def test_level_4_lists_each_new_request(self, row):
        _, _, rows = self._rows(4)
        assert row in rows

    @pytest.mark.parametrize("row", LEVEL_4_ONLY)
    @pytest.mark.parametrize("level", [None, 2, 3])
    def test_a_lower_level_lists_none_of_them(self, row, level):
        _, _, rows = self._rows(level)
        assert row not in rows

    def _read_headers(self, group: int, variation: int, qualifier: int) -> str:
        first, last = INDICES.get(group, (0, 0))
        head = f"{group:02x} {variation:02x} {qualifier:02x}"
        return {
            0x06: head,
            0x07: f"{head} 01",
            0x08: f"{head} 01 00",
            0x00: f"{head} {first:02x} {last:02x}",
            0x01: f"{head} {first:02x} 00 {last:02x} 00",
            0x17: f"{head} 01 {first:02x}",
            0x28: f"{head} 01 00 {first:02x} 00",
        }[qualifier]

    def test_every_request_level_4_lists_is_answered_and_each_response_is_what_is_sent(self):
        outstation, session, _ = self._rows(4)
        table = device_profile.implementation(outstation, session.facts)
        new_groups = (21, 23, 30, 32, 34, 40)
        checked = 0
        for row in table.rows:
            if row.request is None or row.group not in new_groups or row.request[0] != 1:
                continue
            for qualifier in row.request[1]:
                master = Master(outstation.session())
                response = master.read(self._read_headers(row.group, row.variation, qualifier))
                assert not _iin2(response) & (OBJECT_UNKNOWN | PARAM_ERROR), (row, qualifier)
                checked += 1
            if row.response is not None and row.variation:
                response = Master(outstation.session()).read(
                    self._read_headers(row.group, row.variation, 0x06)
                )
                if len(response) > 4:
                    assert tuple(response[4:6]) == (row.group, row.variation), row
        assert checked > 40

    def test_every_write_level_4_lists_is_applied(self):
        outstation, session, _ = self._rows(4)
        table = device_profile.implementation(outstation, session.facts)
        writes = [r for r in table.rows if r.request and r.request[0] == 2 and r.group == 34]
        assert {r.variation for r in writes} == {1, 2, 3}
        value = {1: "03 00", 2: "03 00 00 00", 3: "00 00 40 40"}
        for row in writes:
            for qualifier in row.request[1]:
                head = f"22 {row.variation:02x} {qualifier:02x}"
                body = {
                    0x00: f"{head} 01 01 {value[row.variation]}",
                    0x01: f"{head} 01 00 01 00 {value[row.variation]}",
                    0x17: f"{head} 01 01 {value[row.variation]}",
                    0x28: f"{head} 01 00 01 00 {value[row.variation]}",
                }[qualifier]
                outstation.write_deadbands([(1, 1, 0.0)])
                response = Master(session).write(body)
                assert len(response) == 4 and not _iin2(response), (row, qualifier)
                assert outstation.deadband(1) == 3.0

    def test_the_document_says_deadbands_are_set_over_dnp3_and_not_kept_through_a_restart(self):
        ns = {"d": NAMESPACE}
        outstation = Plant().outstation(4)
        root = device_profile.build(
            outstation, outstation.session(), today=datetime.date(2026, 1, 2)
        )
        assignments = root.find(
            "d:referenceDevice/d:database/d:analogInputGroup/d:configuration/"
            "d:analogDeadbandAssignments",
            ns,
        )
        assert assignments is not None
        assert assignments.find("d:currentValue/d:configurableViaDNP3", ns) is not None
        assert assignments.find("d:capabilities/d:configurableViaOtherMeans", ns) is not None
        preserved = root.find(
            "d:referenceDevice/d:configuration/d:outstationConfig/"
            "d:settingsPreservedThroughDeviceRestart",
            ns,
        )
        assert preserved is not None
        assert preserved.find(".//d:analogDeadbands", ns) is None


SCHEMA = pathlib.Path(__file__).resolve().parent.parent / "schema" / device_profile.SCHEMA_FILE


@pytest.mark.skipif(not SCHEMA.is_file(), reason="the Users Group schema is obtained locally")
@pytest.mark.parametrize("level", [3, 4])
def test_the_document_validates_against_the_schema(level):
    xmlschema = pytest.importorskip("xmlschema")
    outstation = Plant().outstation(level)
    outstation.freeze_all()
    root = device_profile.build(outstation, outstation.session(unsolicited=True))
    errors = list(xmlschema.XMLSchema(str(SCHEMA)).iter_errors(device_profile.render(root)))
    assert errors == []


class TestTheMasterReadsWhatLevel4Sends:
    """The master's decoder reads each new variation an outstation answers with."""

    @staticmethod
    def _objects(response: bytes):
        decoded = decode_objects(response[4:])
        assert decoded.complete, decoded.problem
        return decoded.objects

    def test_floating_point_static_values(self):
        master, _ = _master(4)
        power, voltage = self._objects(master.read("1E 05 00 01 02"))
        assert (power.value, power.flags, power.point) == (1500.0, 0x01, PointType.ANALOG_INPUT)
        assert voltage.value == 240.0
        (setpoint,) = self._objects(master.read("28 03 00 00 00"))
        assert (setpoint.value, setpoint.point) == (12.5, PointType.ANALOG_OUTPUT)

    def test_floating_point_events_with_and_without_time(self):
        master, _ = _with_event(4)
        (timed,) = self._objects(master.read("20 07 06"))
        assert (timed.index, timed.time_ms, timed.event) == (2, 5000, True)
        # The decoder reads a single-precision float, so the value is the nearest one.
        assert timed.value == pytest.approx(244.07, abs=1e-4)
        master, _ = _with_event(4)
        (untimed,) = self._objects(master.read("20 05 06"))
        assert untimed.time_ms is None and untimed.value == pytest.approx(244.07, abs=1e-4)

    def test_frozen_counters_with_time_and_their_events(self):
        outstation = Plant().outstation(4)
        outstation.freeze_all()
        master = Master(outstation.session())
        first, second = self._objects(master.read("15 06 06"))
        assert (first.value, first.time_ms, first.point) == (10, 5000, PointType.FROZEN_COUNTER)
        assert second.value == 20
        events = self._objects(Master(outstation.session()).read("17 06 06"))
        assert [(each.index, each.value, each.time_ms) for each in events] == [
            (0, 10, 5000),
            (1, 20, 5000),
        ]

    def test_deadbands_in_each_variation(self):
        master, _ = _master(4)
        for variation, expected in ((1, 5), (2, 5), (3, 5.0)):
            first, second = self._objects(master.read(f"22 {variation:02x} 00 01 02"))
            assert (first.index, first.value, second.index) == (1, expected, 2)
            assert first.group == 34 and first.point is None


def test_a_floating_point_event_variation_chosen_for_class_polls_is_the_one_the_document_names():
    outstation = Plant().outstation(4)
    session = outstation.session(
        unsolicited=True, analog_event_variation=AnalogEventVariation.FLOAT32_WITH_TIME
    )
    root = device_profile.build(outstation, session, today=datetime.date(2026, 1, 2))
    default = root.find(
        "d:referenceDevice/d:database/d:analogInputGroup/d:configuration/"
        "d:defaultEventVariation/d:currentValue/d:seven",
        {"d": NAMESPACE},
    )
    assert default is not None
    table = device_profile.implementation(outstation, session.facts)
    assert (32, 7) in {(row.group, row.variation) for row in table.rows if row.response}


@pytest.mark.parametrize(("level", "kept"), [(None, False), (3, False), (4, True)])
def test_only_a_level_4_outstation_keeps_the_unscaled_value_of_an_event(level, kept):
    plant = Plant()
    outstation = plant.outstation(level)
    outstation.poll()
    plant.voltage = 244.07
    outstation.poll()
    (event,) = outstation.events.peek(EventClass.CLASS_2, limit=10)
    assert (event.unscaled is not None) is kept
