"""The master's Level 3 and Level 4 requests against this library's own outstation.

Each test wires a master straight to an outstation held to a subset level, in
the same process, and pins the octets of the request and, where the response
is short, of the response. The outstation's own tests check what it answers;
these check that what the master sends is what the outstation takes, and that
the master reads what comes back.
"""

from __future__ import annotations

import pytest
from ied_harness import Dut
from profile_fixtures import document, row
from test_double_bit import Device

from py1815.application import FunctionCode
from py1815.attributes import Variation
from py1815.decode import PointType
from py1815.master import Loopback, profile, requests
from py1815.master.requests import AboveSubsetLevel
from py1815.profile import load
from py1815.profile.binding import Quality
from py1815.profile.model import Composition, Kind
from py1815.subset import SubsetLevel

LEVEL_2, LEVEL_3, LEVEL_4 = SubsetLevel.LEVEL_2, SubsetLevel.LEVEL_3, SubsetLevel.LEVEL_4

#: IIN2.1: the outstation does not know the object asked for.
OBJECT_UNKNOWN = 0x02


def _hex(text: str) -> bytes:
    return bytes.fromhex(text)


def _body(exchange) -> bytes:
    """The object headers and objects of every fragment of the response."""
    return b"".join(fragment.body for fragment in exchange.fragments)


def _sent(exchange) -> bytes:
    """The request after its application control and function code octets."""
    return exchange.request[2:]


def _held(dut, level: SubsetLevel) -> Loopback:
    return Loopback(dut.session, clock=dut.clock, level=level)


def _stamp(dut) -> str:
    """The device clock now, as the six octets of a DNP3 time."""
    return dut.clock.ms().to_bytes(6, "little").hex(" ")


def _empty_events(master: Loopback) -> None:
    master.scan("events")


class TestNamedPoints:
    """D82: ranges go only to an outstation set to Level 3 or 4."""

    def test_level_2_reads_the_whole_group_and_returns_the_points_named(self):
        master = _held(Dut(level=2), LEVEL_2)
        exchange = master.read(analog_inputs=[3, 1])
        # Group 30, variation 0, qualifier 0x06: every analog input.
        assert _sent(exchange) == _hex("1E 00 06")
        # The response carries all four inputs, in g30v1 with flag 0x01, 100 each.
        assert _body(exchange) == _hex("1E 01 00 00 03" + " 01 64 00 00 00" * 4)
        assert [(o.index, o.value) for o in exchange.objects] == [(1, 100), (3, 100)]

    def test_level_3_reads_each_run_of_points_as_a_range(self):
        master = _held(Dut(level=3), LEVEL_3)
        exchange = master.read(analog_inputs=[3, 1])
        # Two start-stop headers, qualifier 0x00: 1..1 and 3..3.
        assert _sent(exchange) == _hex("1E 00 00 01 01 1E 00 00 03 03")
        assert _body(exchange) == _hex(
            "1E 01 00 01 01 01 64 00 00 00 1E 01 00 03 03 01 64 00 00 00"
        )
        assert [(o.index, o.value) for o in exchange.objects] == [(1, 100), (3, 100)]

    def test_level_2_reads_a_refused_request_again_one_point_type_at_a_time(self):
        # Below Level 4 the outstation serves no double-bit input, so a read
        # of group 3 beside group 1 is refused whole. Each type is then read
        # whole on its own, once, however many runs of points it names, and
        # the binary input is still reported.
        device = Device(level=2)
        valves = [row(f"Valve {index}", index) for index in (0, 2)]
        tables = load.resolve(
            document({"BI": [row("Alarm", 0, event_class=1)], "DBI": valves}), Composition()
        )
        master = Loopback(device.session, clock=device.clock)
        wanted = [tables.point(Kind.DBI, 0), tables.point(Kind.DBI, 2), tables.point(Kind.BI, 0)]
        readings = profile.run(master, profile.read_plan(wanted))
        assert [_sent(each) for each in readings.exchanges] == [
            _hex("01 00 06 03 00 06"),
            _hex("03 00 06"),
            _hex("01 00 06"),
        ]
        assert [reading.reported for reading in readings.readings] == [False, False, True]


class TestIndications:
    def test_level_3_reads_the_16_indication_bits_with_the_restart_bit_set(self):
        master = _held(Dut(level=3), LEVEL_3)
        exchange = master.read_indications()
        assert _sent(exchange) == _hex("50 01 00 00 0F")
        # Group 80 variation 1, indices 0 to 15: IIN1.7, device restart, is set.
        assert _body(exchange) == _hex("50 01 00 00 0F 80 00")

    def test_a_write_of_index_7_clears_the_restart_bit_read_back_at_level_4(self):
        master = _held(Dut(level=4), LEVEL_4)
        written = master.clear_restart()
        assert _sent(written) == _hex("50 01 00 07 07 00") and _body(written) == b""
        assert _body(master.read_indications()) == _hex("50 01 00 00 0F 00 00")

    def test_level_2_refuses_the_read_before_it_is_sent(self):
        master = _held(Dut(level=2), LEVEL_2)
        with pytest.raises(AboveSubsetLevel, match="Level 3 request"):
            master.read_indications()


class TestTime:
    @pytest.mark.parametrize("level", [LEVEL_3, LEVEL_4])
    def test_the_time_written_is_the_time_read(self, level):
        dut = Dut(level=level)
        master = _held(dut, level)
        # 1 700 000 000 000 ms is 0x018BCFE56800.
        written = master.write_time(1_700_000_000_000)
        assert _sent(written) == _hex("32 01 07 01 00 68 E5 CF 8B 01")
        read = master.read_time()
        assert _sent(read) == _hex("32 01 07 01")
        assert _body(read) == _hex("32 01 07 01 00 68 E5 CF 8B 01")
        dut.clock.advance(1.5)
        assert [o.time_ms for o in master.read_time().objects] == [1_700_000_001_500]

    def test_level_2_refuses_a_read_of_the_time(self):
        with pytest.raises(AboveSubsetLevel):
            _held(Dut(level=2), LEVEL_2).read_time()


class TestAssignClass:
    """ASSIGN_CLASS moves the events of a point to another class (D110)."""

    @pytest.mark.parametrize("level", [LEVEL_3, LEVEL_4])
    def test_an_analog_input_moved_to_class_2_reports_there(self, level):
        dut = Dut(level=level)
        master = _held(dut, level)
        _empty_events(master)
        exchange = master.assign_class(2, analog_inputs=[0])
        # Group 60 variation 3 (class 2), then g30v0 0..0.
        assert _sent(exchange) == _hex("3C 03 06 1E 00 00 00 00") and _body(exchange) == b""
        dut.step(0)
        assert _body(master.scan("class1")) == b""
        assert [(o.group, o.index) for o in master.scan("class2").objects] == [(32, 0)]

    def test_class_0_stops_the_events_and_keeps_the_point_in_class_0(self):
        dut = Dut(level=4)
        master = _held(dut, LEVEL_4)
        _empty_events(master)
        exchange = master.assign_class(0, analog_inputs=[0])
        # Group 60 variation 1 turns events off (IEEE 1815-2012 4.1.5.3).
        assert _sent(exchange) == _hex("3C 01 06 1E 00 00 00 00")
        dut.step(0)
        assert _body(master.scan("events")) == b""
        static = [o.index for o in master.scan("class0").objects if o.group == 30]
        assert 0 in static

    def test_a_counter_moved_to_class_1_reports_a_flag_change_there(self):
        dut = Dut(level=3)
        master = _held(dut, LEVEL_3)
        _empty_events(master)
        assert _sent(master.assign_class(1, counters=[1])) == _hex("3C 02 06 14 00 00 01 01")
        dut.clock.advance(0.01)
        dut.quality[(Kind.CTR, 1)] = Quality.COMM_LOST
        dut.outstation.poll()
        # g22v1, index 1, COMM_LOST (0x04), count 5 (D124).
        assert _body(master.scan("class1")) == _hex("16 01 17 01 01 04 05 00 00 00")

    def test_output_status_moves_class_at_level_4(self):
        dut = Dut(level=4, output_status=True)
        master = _held(dut, LEVEL_4)
        _empty_events(master)
        assert _sent(master.assign_class(1, binary_outputs=[2])) == _hex("3C 02 06 0A 00 00 02 02")
        assert _sent(master.assign_class(2, analog_outputs=[3])) == _hex("3C 03 06 28 00 00 03 03")
        dut.clock.advance(0.01)
        dut.quality[(Kind.BO, 2)] = Quality.COMM_LOST
        dut.quality[(Kind.AO, 3)] = Quality.COMM_LOST
        dut.outstation.poll()
        stamp = _stamp(dut)
        assert _body(master.scan("class1")) == _hex(f"0B 02 17 01 02 04 {stamp}")
        assert _body(master.scan("class2")) == _hex(f"2A 03 17 01 03 04 00 00 00 00 {stamp}")
        assert _body(master.scan("class3")) == b""

    def test_a_double_bit_input_moves_class_at_level_4(self):
        device = Device(level=4)
        master = Loopback(device.session, clock=device.clock, level=LEVEL_4)
        _empty_events(master)
        # Point 0 is in class 1 in the tables; group 3 0..0 names it.
        exchange = master.assign_class(2, double_bit_inputs=[0])
        assert _sent(exchange) == _hex("3C 03 06 03 00 00 00 00")
        device.move(0, 1)
        # g4v2, index 0, DETERMINED_OFF (0x40) with ONLINE, then the time.
        stamp = device.clock.ms().to_bytes(6, "little").hex(" ")
        assert _body(master.scan("class1")) == b""
        assert _body(master.scan("class2")) == _hex(f"04 02 17 01 00 41 {stamp}")

    def test_level_3_refuses_output_status_and_double_bit_inputs(self):
        master = _held(Dut(level=3), LEVEL_3)
        for send in (
            lambda: master.assign_class(1, binary_outputs=[0]),
            lambda: master.assign_class(1, analog_outputs=[0]),
            lambda: master.assign_class(1, double_bit_inputs=[0]),
        ):
            with pytest.raises(AboveSubsetLevel, match="Level 4 request"):
                send()


class TestDeadbands:
    def test_a_deadband_written_is_the_deadband_read(self):
        master = _held(Dut(level=4), LEVEL_4)
        written = master.write_deadbands(1, {0: 50})
        # g34v1, index 0..0, 50 in 16 bits.
        assert _sent(written) == _hex("22 01 00 00 00 32 00") and _body(written) == b""
        read = master.read_deadbands(1, start=0, stop=0)
        assert _sent(read) == _hex("22 01 00 00 00")
        assert _body(read) == _hex("22 01 00 00 00 32 00")
        assert [(o.group, o.index, o.value) for o in read.objects] == [(34, 0, 50)]

    def test_level_3_refuses_a_deadband_request(self):
        with pytest.raises(AboveSubsetLevel, match="Level 4 request"):
            _held(Dut(level=3), LEVEL_3).read_deadbands()


class TestDeviceAttributes:
    def test_every_attribute_is_read_and_none_is_254_or_255(self):
        master = _held(Dut(level=4), LEVEL_4)
        exchange = master.read_attributes()
        assert _sent(exchange) == _hex("00 FE 06")
        found = [o.variation for o in exchange.objects]
        assert found == sorted(found) and found
        assert Variation.ALL_ATTRIBUTES not in found
        assert Variation.LIST_OF_VARIATIONS not in found
        assert all(o.attribute is not None for o in exchange.objects)

    def test_the_list_marks_the_writable_attributes(self):
        master = _held(Dut(level=4), LEVEL_4)
        exchange = master.read_attributes(255)
        assert _sent(exchange) == _hex("00 FF 06")
        (listing,) = exchange.objects
        writable = {variation for variation, can in listing.attribute.value if can}
        assert writable == {240, 245, 246, 247}

    def test_a_name_written_is_the_name_read(self):
        master = _held(Dut(level=4), LEVEL_4)
        written = master.write_attribute(247, "Feeder 7")
        # Variation 247, set 0..0, VSTR (1), 8 octets of text.
        assert _sent(written) == _hex("00 F7 00 00 00 01 08 46 65 65 64 65 72 20 37")
        assert _body(written) == b""
        read = master.read_attributes(247)
        assert _sent(read) == _hex("00 F7 00 00 00")
        assert _body(read) == _hex("00 F7 00 00 00 01 08 46 65 65 64 65 72 20 37")
        assert [o.attribute.value for o in read.objects] == ["Feeder 7"]

    def test_the_master_refuses_and_the_outstation_does_not_know_group_0_below_level_4(self):
        dut = Dut(level=3)
        master = _held(dut, LEVEL_3)
        with pytest.raises(AboveSubsetLevel, match="Level 4 request"):
            master.read_attributes()
        with pytest.raises(AboveSubsetLevel, match="Level 4 request"):
            master.write_attribute(247, "x")
        # Sent anyway through the raw interface, the outstation does not know it.
        raw = master.request(FunctionCode.READ, requests.read_attributes())
        assert raw.iin.second & OBJECT_UNKNOWN


class TestLevel4EventGroups:
    def test_double_bit_inputs_and_their_events_are_decoded(self):
        device = Device(level=4)
        master = Loopback(device.session, clock=device.clock, level=LEVEL_4)
        device.set_states(0, 1, 2, 3, 2, 1)
        device.outstation.poll()
        _empty_events(master)
        static = master.read_group(3)
        assert _sent(static) == _hex("03 00 06")
        assert [(o.point, o.index, o.value) for o in static.objects] == [
            (PointType.DOUBLE_BIT_INPUT, index, state)
            for index, state in enumerate((0, 1, 2, 3, 2, 1))
        ]
        device.move(0, 2)
        events = master.read_group(4)
        assert _sent(events) == _hex("04 00 06")
        assert [(o.group, o.index, o.value, o.event) for o in events.objects] == [(4, 0, 2, True)]

    def test_output_events_are_decoded_and_command_events_are_none(self):
        dut = Dut(level=4, output_status=True)
        master = _held(dut, LEVEL_4)
        _empty_events(master)
        dut.clock.advance(0.01)
        dut.quality[(Kind.BO, 2)] = Quality.COMM_LOST
        dut.quality[(Kind.AO, 3)] = Quality.COMM_LOST
        dut.outstation.poll()
        binary = master.read_group(11)
        assert _sent(binary) == _hex("0B 00 06")
        assert [(o.point, o.index, o.flags, o.event) for o in binary.objects] == [
            (PointType.BINARY_OUTPUT, 2, 0x04, True)
        ]
        analog = master.read_group(42)
        assert _sent(analog) == _hex("2A 00 06")
        assert [(o.point, o.index, o.value, o.flags) for o in analog.objects] == [
            (PointType.ANALOG_OUTPUT, 3, 0, 0x04)
        ]
        # No command events are generated (D116): a null response.
        for group in (13, 43):
            exchange = master.read_group(group)
            assert _sent(exchange) == bytes([group, 0, 0x06])
            assert exchange.complete and _body(exchange) == b""
            assert not exchange.iin.second & OBJECT_UNKNOWN
