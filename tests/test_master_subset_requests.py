"""The requests a master sends to Level 3 and Level 4 outstations.

Every request is pinned to octets written out by hand, so a mistake in the
builders is not hidden by an outstation that reads it the same way. The
master refuses a request above the subset level it was told the outstation
has, before any frame is sent (IEEE 1815-2012 14.7.2). Reads by variation
and by range are also carried out against the simulated DER, which answers
them.
"""

from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815.application import FunctionCode
from py1815.decode import PointType
from py1815.master import Loopback, Master, requests
from py1815.master.api import Outstation
from py1815.master.requests import AboveSubsetLevel
from py1815.master.service import Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer
from py1815.subset import SubsetLevel

LEVEL_2, LEVEL_3, LEVEL_4 = SubsetLevel.LEVEL_2, SubsetLevel.LEVEL_3, SubsetLevel.LEVEL_4


def _hex(text: str) -> bytes:
    return bytes.fromhex(text)


class TestWhatTravels:
    def test_a_group_is_read_by_a_variation_with_no_range(self):
        # Group 30 variation 1, qualifier 0x06: every object.
        assert requests.read_group(30, 1) == _hex("1E 01 06")

    def test_variation_0_asks_for_the_default_variation(self):
        assert requests.read_group(1) == _hex("01 00 06")

    def test_a_range_is_one_start_stop_header(self):
        # Group 30 variation 0, qualifier 0x00, start 2, stop 4.
        assert requests.read_group(30, 0, start=2, stop=4) == _hex("1E 00 00 02 04")

    def test_a_range_past_255_takes_16_bit_limits(self):
        # Qualifier 0x01, start 300 (0x012C), stop 301 (0x012D).
        assert requests.read_group(30, 1, start=300, stop=301) == _hex("1E 01 01 2C 01 2D 01")

    def test_indices_are_an_index_list_in_the_order_given(self):
        # Qualifier 0x17: a count of 2, then indices 5 and 1.
        assert requests.read_group(1, 2, indices=[5, 1]) == _hex("01 02 17 02 05 01")

    def test_indices_past_255_take_16_bit_counts_and_indices(self):
        # Qualifier 0x28: a count of 2, then 1 and 300, each in 16 bits.
        assert requests.read_group(30, 0, indices=[1, 300]) == _hex("1E 00 28 02 00 01 00 2C 01")

    def test_the_time_is_read_as_one_object(self):
        # Group 50 variation 1, qualifier 0x07 (count of one octet), count 1.
        assert requests.read_time() == _hex("32 01 07 01")

    def test_the_internal_indications_are_read_as_16_bits_by_default(self):
        # Group 80 variation 1, qualifier 0x00, index 0 to 15.
        assert requests.read_indications() == _hex("50 01 00 00 0F")

    def test_a_narrower_range_of_indications_can_be_read(self):
        assert requests.read_indications(7, 8) == _hex("50 01 00 07 08")

    def test_an_assignment_is_a_class_object_and_the_points_that_follow(self):
        body = requests.assign_class([(1, {PointType.ANALOG_INPUT: [0, 1, 2]})])
        # Group 60 variation 2 (class 1), qualifier 0x06, then group 30
        # variation 0, qualifier 0x00, start 0, stop 2.
        assert body == _hex("3C 02 06 1E 00 00 00 02")

    def test_class_2_and_3_are_variations_3_and_4_of_group_60(self):
        assert requests.assign_class([(2, {PointType.COUNTER: None})]) == _hex("3C 03 06 14 00 06")
        assert requests.assign_class([(3, {PointType.BINARY_INPUT: [4]})]) == _hex(
            "3C 04 06 01 00 00 04 04"
        )

    def test_class_0_turns_events_off_with_variation_1_of_group_60(self):
        # Variation 1 turns events off, and does not mean class 0 data
        # (IEEE 1815-2012 4.1.5.3).
        assert requests.assign_class([(0, {PointType.BINARY_INPUT: None})]) == _hex(
            "3C 01 06 01 00 06"
        )

    def test_several_sets_follow_one_another_each_with_its_class_object(self):
        body = requests.assign_class(
            [(1, {PointType.ANALOG_INPUT: [0]}), (3, {PointType.COUNTER: [5, 6]})]
        )
        assert body == _hex("3C 02 06 1E 00 00 00 00 3C 04 06 14 00 00 05 06")

    def test_deadbands_of_consecutive_points_share_a_header(self):
        # Group 34 variation 1, qualifier 0x00, start 3, stop 4, then 10 and
        # 20 as 16-bit values, least significant octet first.
        assert requests.write_deadbands(1, {3: 10, 4: 20}) == _hex("22 01 00 03 04 0A 00 14 00")

    def test_deadbands_of_points_apart_take_a_header_each(self):
        assert requests.write_deadbands(1, {5: 2, 1: 1}) == _hex(
            "22 01 00 01 01 01 00 22 01 00 05 05 02 00"
        )

    def test_a_32_bit_deadband_takes_four_octets(self):
        assert requests.write_deadbands(2, {0: 65536}) == _hex("22 02 00 00 00 00 00 01 00")

    def test_a_floating_point_deadband_is_single_precision(self):
        # 1.5 is 0x3FC00000.
        assert requests.write_deadbands(3, {0: 1.5}) == _hex("22 03 00 00 00 00 00 C0 3F")

    def test_every_attribute_is_asked_for_with_variation_254_and_no_range(self):
        assert requests.read_attributes() == _hex("00 FE 06")

    def test_the_list_of_attributes_is_variation_255_with_no_range(self):
        assert requests.read_attributes(255) == _hex("00 FF 06")

    def test_one_attribute_is_a_range_of_its_set_alone(self):
        # The read of the maximum receive fragment size in IEEE 1815-2012 5.5.5.
        assert requests.read_attributes(241) == _hex("00 F1 00 00 00")

    def test_an_attribute_set_other_than_0_is_named_in_the_range(self):
        assert requests.read_attributes(254, 2) == _hex("00 FE 00 02 02")

    def test_a_text_attribute_is_written_with_its_data_type_and_length(self):
        # Variation 247, VSTR (data type 1), 2 octets: "ab".
        assert requests.write_attribute(247, "ab") == _hex("00 F7 00 00 00 01 02 61 62")

    def test_a_number_attribute_takes_the_fewest_octets_of_1_2_or_4(self):
        # Variation 240, UINT (data type 2).
        assert requests.write_attribute(240, 200) == _hex("00 F0 00 00 00 02 01 C8")
        assert requests.write_attribute(240, 2048) == _hex("00 F0 00 00 00 02 02 00 08")
        assert requests.write_attribute(240, 70000) == _hex("00 F0 00 00 00 02 04 70 11 01 00")


class TestWhatIsRefused:
    @pytest.mark.parametrize(
        ("call", "says"),
        [
            (lambda: requests.read_group(30, 0, start=1), "both start and stop"),
            (lambda: requests.read_group(30, 0, start=1, stop=2, indices=[1]), "not both"),
            (lambda: requests.read_group(256), "a group is a whole number from 0 to 255"),
            (lambda: requests.read_group(30, -1), "a variation is a whole number"),
            (lambda: requests.read_group(30, 0, start=5, stop=4), "ends before it begins"),
            (lambda: requests.read_group(30, 0, indices=[]), "at least one point"),
            (lambda: requests.read_indications(5, 70000), "does not fit a 16-bit index"),
            (lambda: requests.assign_class([]), "at least one set"),
            (
                lambda: requests.assign_class([(4, {PointType.COUNTER: None})]),
                "4 is not an event class",
            ),
            (
                lambda: requests.assign_class([(True, {PointType.COUNTER: None})]),
                "True is not an event class",
            ),
            (lambda: requests.write_deadbands(4, {0: 1}), "not a deadband variation"),
            (lambda: requests.write_deadbands(1, {}), "at least one deadband"),
            (lambda: requests.write_deadbands(1, {0: 65536}), "does not fit this variation"),
            (lambda: requests.write_deadbands(1, {0: 1.5}), "a whole number"),
            (lambda: requests.write_deadbands(1, {0: -1}), "does not fit this variation"),
            (lambda: requests.write_deadbands(3, {0: -1.0}), "zero or more"),
            (lambda: requests.write_deadbands(3, {0: float("nan")}), "zero or more"),
            (lambda: requests.write_deadbands(1, {0: True}), "is a number"),
            (lambda: requests.read_attributes(0), "1 to 255"),
            (lambda: requests.write_attribute(241, 1), "cannot be written"),
            (lambda: requests.write_attribute(240, -1), "a whole number from 0"),
            (lambda: requests.write_attribute(240, "1"), "a whole number from 0"),
            (lambda: requests.write_attribute(247, "café"), "visible ASCII"),
            (lambda: requests.write_attribute(247, 5), "visible ASCII"),
            (lambda: requests.write_attribute(247, "x" * 256), "at most 255"),
        ],
    )
    def test_a_request_that_cannot_be_built_is_refused_with_what_is_wrong(self, call, says):
        with pytest.raises(ValueError, match=says):
            call()

    def test_infinity_is_a_deadband_that_prevents_events(self):
        # A deadband of positive infinity prevents events (IEEE 1815-2012 A.18.3).
        assert requests.write_deadbands(3, {0: float("inf")}) == _hex("22 03 00 00 00 00 00 80 7F")


class TestWhichLevelARequestNeeds:
    @pytest.mark.parametrize(
        ("group", "variation", "options", "level"),
        [
            # Level 2 reads: every object, in the default variation.
            (1, 0, {}, LEVEL_2),
            (30, 0, {}, LEVEL_2),
            (2, 1, {}, LEVEL_2),
            (2, 3, {}, LEVEL_2),
            (22, 0, {}, LEVEL_2),
            (32, 0, {}, LEVEL_2),
            # Level 3 adds a named variation and a range of static points.
            (30, 1, {}, LEVEL_3),
            (1, 2, {}, LEVEL_3),
            (30, 0, {"ranged": True}, LEVEL_3),
            (1, 0, {"ranged": True}, LEVEL_3),
            (32, 1, {}, LEVEL_3),
            (22, 1, {}, LEVEL_3),
            (22, 2, {}, LEVEL_3),
            (23, 0, {}, LEVEL_3),
            (23, 1, {}, LEVEL_3),
            (50, 1, {}, LEVEL_3),
            (80, 1, {"ranged": True}, LEVEL_3),
            # An index list is required at no level (TB2016-003b lists it as
            # subset-independent), so it is taken to need Level 4, with the
            # groups and variations only Level 4 defines.
            (30, 0, {"indexed": True}, LEVEL_4),
            (30, 5, {}, LEVEL_4),
            (40, 3, {}, LEVEL_4),
            (3, 0, {}, LEVEL_4),
            (4, 0, {}, LEVEL_4),
            (11, 0, {}, LEVEL_4),
            (13, 0, {}, LEVEL_4),
            (34, 0, {}, LEVEL_4),
            (42, 0, {}, LEVEL_4),
            (43, 0, {}, LEVEL_4),
            (0, 254, {}, LEVEL_4),
            # A group or a variation the tables do not name is taken to need
            # the highest level, as is an event group read by range.
            (110, 0, {}, LEVEL_4),
            (10, 1, {}, LEVEL_4),
            (22, 5, {}, LEVEL_4),
            (30, 6, {}, LEVEL_4),
            (32, 6, {}, LEVEL_4),
            (32, 8, {}, LEVEL_4),
            (40, 4, {}, LEVEL_4),
            (50, 4, {}, LEVEL_4),
            (23, 1, {"ranged": True}, LEVEL_4),
        ],
    )
    def test_the_level_of_a_read(self, group, variation, options, level):
        assert requests.read_group_level(group, variation, **options) is level

    def test_an_assignment_of_inputs_and_counters_is_level_3(self):
        sets = [(1, {PointType.ANALOG_INPUT: None, PointType.COUNTER: [1]})]
        assert requests.assign_class_level(sets) is LEVEL_3

    @pytest.mark.parametrize(
        "point", [PointType.DOUBLE_BIT_INPUT, PointType.BINARY_OUTPUT, PointType.ANALOG_OUTPUT]
    )
    def test_an_assignment_of_double_bit_inputs_or_output_status_is_level_4(self, point):
        assert requests.assign_class_level([(1, {point: None})]) is LEVEL_4

    def test_a_master_is_held_to_level_2_until_told_otherwise(self):
        assert requests.DEFAULT_LEVEL is LEVEL_2


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


class _Counting(Loopback):
    """A loopback that counts the requests it was asked to make."""

    asked = 0

    def _exchange(self, function, body, *, broadcast=None):
        self.asked += 1
        return super()._exchange(function, body, broadcast=broadcast)


def _held_to(simulation: der.Simulation, level) -> _Counting:
    return _Counting(simulation.outstation.session(), level=level)


#: Each request a master offers, at the lowest level that allows it.
REQUESTS = [
    ("read_group", lambda master: master.read_group(30, 1), LEVEL_3, "1E 01 06"),
    (
        "read_group_range",
        lambda master: master.read_group(30, 0, start=0, stop=1),
        LEVEL_3,
        "1E 00 00 00 01",
    ),
    (
        "read_group_indices",
        lambda master: master.read_group(30, 0, indices=[1]),
        LEVEL_4,
        "1E 00 17 01 01",
    ),
    ("read_time", lambda master: master.read_time(), LEVEL_3, "32 01 07 01"),
    ("read_indications", lambda master: master.read_indications(), LEVEL_3, "50 01 00 00 0F"),
    (
        "assign_class",
        lambda master: master.assign_class(1, analog_inputs=[0]),
        LEVEL_3,
        "3C 02 06 1E 00 00 00 00",
    ),
    (
        "assign_class_outputs",
        lambda master: master.assign_class(2, binary_outputs="all"),
        LEVEL_4,
        "3C 03 06 0A 00 06",
    ),
    ("read_deadbands", lambda master: master.read_deadbands(), LEVEL_4, "22 00 06"),
    (
        "read_deadbands_range",
        lambda master: master.read_deadbands(2, start=1, stop=2),
        LEVEL_4,
        "22 02 00 01 02",
    ),
    (
        "write_deadbands",
        lambda master: master.write_deadbands(1, {0: 5}),
        LEVEL_4,
        "22 01 00 00 00 05 00",
    ),
    ("read_attributes", lambda master: master.read_attributes(), LEVEL_4, "00 FE 06"),
    (
        "write_attribute",
        lambda master: master.write_attribute(246, "7"),
        LEVEL_4,
        "00 F6 00 00 00 01 01 37",
    ),
]

FUNCTIONS = {
    "assign_class": FunctionCode.ASSIGN_CLASS,
    "assign_class_outputs": FunctionCode.ASSIGN_CLASS,
    "write_deadbands": FunctionCode.WRITE,
    "write_attribute": FunctionCode.WRITE,
}


class TestTheLevelGatesWhatIsSent:
    @pytest.mark.parametrize(
        ("send", "needed"), [(each[1], each[2]) for each in REQUESTS], ids=[r[0] for r in REQUESTS]
    )
    def test_a_request_above_the_level_is_refused_and_nothing_is_sent(
        self, simulation, send, needed
    ):
        for level in SubsetLevel:
            if level >= needed:
                continue
            master = _held_to(simulation, level)
            with pytest.raises(AboveSubsetLevel) as refused:
                send(master)
            assert master.asked == 0
            assert f"Level {int(needed)} request" in str(refused.value)
            assert f"set to Level {int(level)}" in str(refused.value)

    @pytest.mark.parametrize(
        ("send", "needed", "octets", "name"),
        [(each[1], each[2], each[3], each[0]) for each in REQUESTS],
        ids=[r[0] for r in REQUESTS],
    )
    def test_a_request_at_or_above_the_level_is_sent_with_these_octets(
        self, simulation, send, needed, octets, name
    ):
        for level in SubsetLevel:
            if level < needed:
                continue
            master = _held_to(simulation, level)
            exchange = send(master)
            assert master.asked == 1
            assert exchange.function is FUNCTIONS.get(name, FunctionCode.READ)
            assert exchange.request[2:] == _hex(octets)

    def test_the_error_says_what_to_do_about_it(self, simulation):
        with pytest.raises(AboveSubsetLevel, match="Set its level to 3 or higher only if"):
            _held_to(simulation, LEVEL_2).read_time()

    def test_the_refusal_is_a_value_error_so_the_service_reports_it_as_a_request_error(self):
        assert issubclass(AboveSubsetLevel, ValueError)

    def test_the_raw_interface_is_not_held_to_the_level(self, simulation):
        master = _held_to(simulation, LEVEL_2)
        exchange = master.request(FunctionCode.READ, requests.read_time())
        assert exchange.request[2:] == _hex("32 01 07 01")

    def test_the_level_must_be_2_3_or_4(self, simulation):
        for given in (1, 5, "3", 3.0, True, None):
            with pytest.raises(ValueError, match="level must be 2, 3 or 4"):
                Loopback(simulation.outstation.session(), level=given)

    def test_what_is_wrong_with_a_request_is_said_before_its_level(self, simulation):
        with pytest.raises(ValueError, match="both start and stop") as refused:
            _held_to(simulation, LEVEL_2).read_group(30, 0, start=1)
        assert not isinstance(refused.value, AboveSubsetLevel)

    def test_a_request_names_at_least_one_point_to_assign(self, simulation):
        with pytest.raises(ValueError, match="names at least one point"):
            _held_to(simulation, LEVEL_3).assign_class(1)


class TestAgainstTheSimulatedDer:
    """The simulated DER answers a read by variation and by range."""

    def test_a_read_by_variation_returns_the_variation_asked_for(self, simulation):
        exchange = _held_to(simulation, LEVEL_3).read_group(30, 1)
        assert exchange.complete and exchange.request[2:] == _hex("1E 01 06")
        analogs = [each for each in exchange.objects if each.group == 30]
        assert analogs and {each.variation for each in analogs} == {1}

    def test_a_read_by_range_returns_the_points_of_the_range_and_no_others(self, simulation):
        exchange = _held_to(simulation, LEVEL_3).read_group(30, 0, start=0, stop=1)
        assert exchange.complete
        assert {each.index for each in exchange.objects if each.group == 30} <= {0, 1}
        assert any(each.group == 30 for each in exchange.objects)

    def test_a_read_of_binary_inputs_by_variation_2_returns_flags(self, simulation):
        exchange = _held_to(simulation, LEVEL_3).read_group(1, 2, start=0, stop=3)
        found = [each for each in exchange.objects if each.group == 1]
        assert found and {each.variation for each in found} == {2}
        assert {each.index for each in found} <= {0, 1, 2, 3}

    def test_a_read_at_level_2_by_default_variation_needs_no_level(self, simulation):
        master = _held_to(simulation, LEVEL_2)
        exchange = master.read_group(30)
        assert exchange.request[2:] == _hex("1E 00 06")
        assert any(each.group == 30 for each in exchange.objects)


# --------------------------------------------------------- over a connection


@pytest_asyncio.fixture
async def served(simulation):
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


class TestOverAConnection:
    @pytest.mark.asyncio
    async def test_the_level_is_given_when_the_outstation_is_added(self, served):
        async with asyncio.timeout(10):
            master = Master()
            try:
                lab = await master.add("lab", host="127.0.0.1", port=served.port, level=3)
                assert lab.level is LEVEL_3
                exchange = await lab.read_group(30, 1)
                assert exchange.complete and exchange.request[2:] == _hex("1E 01 06")
            finally:
                await master.close()

    @pytest.mark.asyncio
    async def test_an_outstation_with_no_level_given_is_held_to_level_2(self, served):
        async with asyncio.timeout(10):
            master = Master()
            try:
                lab = await master.add("lab", host="127.0.0.1", port=served.port, manual=True)
                assert lab.level is LEVEL_2
                with pytest.raises(AboveSubsetLevel):
                    lab.read_group(30, 1)
                assert [entry for entry in lab.trace.since() if entry.direction == "tx"] == []
            finally:
                await master.close()

    def test_a_level_that_is_not_one_is_refused_when_the_outstation_is_made(self):
        with pytest.raises(ValueError, match="level must be 2, 3 or 4"):
            Outstation("lab", host="127.0.0.1", level=1)

    def test_the_level_can_be_raised_once_the_outstation_is_known_to_support_it(self):
        lab = Outstation("lab", host="127.0.0.1")
        lab.level = SubsetLevel.parse(4)
        assert lab.level is LEVEL_4


# ---------------------------------------------------------------- the service


def _ask(service: Service, op: str, **params):
    return service.handle({"op": op, "outstation": "lab", "params": params})


@pytest_asyncio.fixture
async def reading(served):
    """A service that does not command, with the DER added by hand at Level 3."""
    service = Service()
    answer = await service.handle(
        {
            "op": "add",
            "params": {
                "name": "lab",
                "host": "127.0.0.1",
                "port": served.port,
                "manual": True,
                "level": 3,
            },
        }
    )
    assert answer["ok"], answer
    try:
        yield service
    finally:
        await service.close()


@pytest_asyncio.fixture
async def commanding(served):
    """A service started to command, with the DER added by hand at Level 4."""
    service = Service(allow_control=True)
    answer = await service.handle(
        {
            "op": "add",
            "params": {
                "name": "lab",
                "host": "127.0.0.1",
                "port": served.port,
                "manual": True,
                "level": 4,
            },
        }
    )
    assert answer["ok"], answer
    try:
        yield service
    finally:
        await service.close()


class TestTheService:
    @pytest.mark.asyncio
    async def test_the_level_is_given_in_add_and_shown_in_the_outstation(self, reading):
        (lab,) = (await reading.handle({"op": "status"}))["result"]["outstations"]
        assert lab["level"] == 3

    @pytest.mark.asyncio
    async def test_an_outstation_added_with_no_level_is_level_2(self, served):
        service = Service()
        try:
            await service.handle(
                {"op": "add", "params": {"name": "lab", "host": "127.0.0.1", "port": served.port}}
            )
            (lab,) = (await service.handle({"op": "status"}))["result"]["outstations"]
            assert lab["level"] == 2
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_a_level_that_is_not_one_is_refused(self, served):
        service = Service()
        try:
            answer = await service.handle(
                {
                    "op": "add",
                    "params": {"name": "x", "host": "127.0.0.1", "port": served.port, "level": 7},
                }
            )
            assert answer == {
                "id": None,
                "ok": False,
                "error": {"kind": "request", "message": "level must be 2, 3 or 4, not 7"},
            }
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_read_group_sends_the_read_and_returns_its_exchange(self, reading):
        answer = await _ask(reading, "read_group", group=30, variation=1, start=0, stop=1)
        assert answer["ok"], answer
        assert answer["result"]["request"][4:] == "1e01000001"
        assert answer["result"]["function"] == "READ"
        assert answer["result"]["outcome"] == "complete"

    @pytest.mark.asyncio
    async def test_read_group_names_a_list_of_indices(self, commanding):
        answer = await _ask(commanding, "read_group", group=1, variation=2, indices=[0, 2])
        assert answer["ok"] and answer["result"]["request"][4:] == "010217020002"

    @pytest.mark.asyncio
    async def test_a_request_above_the_level_is_a_request_error_and_sends_nothing(self, reading):
        answer = await _ask(reading, "read_attributes")
        assert answer["ok"] is False and answer["error"]["kind"] == "request"
        assert "Level 4 request" in answer["error"]["message"]
        assert "set to Level 3" in answer["error"]["message"]
        assert (await _ask(reading, "trace"))["result"]["frames"] == []

    @pytest.mark.asyncio
    async def test_the_time_and_the_indications_are_read_at_level_3(self, reading):
        time = await _ask(reading, "read_time")
        indications = await _ask(reading, "read_indications", start=4, stop=7)
        assert time["ok"] and time["result"]["request"][4:] == "32010701"
        assert indications["ok"] and indications["result"]["request"][4:] == "5001000407"

    @pytest.mark.asyncio
    async def test_attributes_are_read_at_level_4(self, commanding):
        everything = await _ask(commanding, "read_attributes")
        one = await _ask(commanding, "read_attributes", variation=241, attribute_set=0)
        assert everything["result"]["request"][4:] == "00fe06"
        assert one["result"]["request"][4:] == "00f1000000"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("op", "params", "says"),
        [
            ("read_group", {}, "names the group"),
            ("read_group", {"group": "30"}, "group is a whole number"),
            ("read_group", {"group": 30, "indices": "1"}, "indices is a list"),
            ("read_group", {"group": 30, "start": 1}, "both start and stop"),
            ("read_attributes", {"variation": True}, "variation is a whole number"),
        ],
    )
    async def test_a_read_that_cannot_be_made_says_what_is_wrong(
        self, commanding, op, params, says
    ):
        answer = await _ask(commanding, op, **params)
        assert answer["ok"] is False and answer["error"]["kind"] == "request"
        assert says in answer["error"]["message"]


COMMANDS = [
    ("assign_class", {"event_class": 1, "points": {"ai": [0]}}, "16"),
    ("write_deadbands", {"variation": 1, "values": {"0": 5}}, "02"),
    ("write_attribute", {"variation": 247, "value": "x"}, "02"),
]


class TestTheServiceCommands:
    """Assigning a class and writing a deadband or an attribute change the outstation."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("op", "params", "_function"), COMMANDS)
    async def test_without_allow_control_they_are_refused_and_nothing_is_sent(
        self, reading, op, params, _function
    ):
        # The service holds the DER at Level 3: a Level 4 write would be a
        # request error if it got as far as the level, so this also shows
        # that the permission is asked first, as for every other command.
        answer = await _ask(reading, op, **params)
        assert answer["ok"] is False and answer["error"]["kind"] == "not_allowed"
        assert (await _ask(reading, "trace"))["result"]["frames"] == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("op", "params", "function"), COMMANDS)
    async def test_with_allow_control_they_are_sent_once_with_the_function_code(
        self, commanding, op, params, function
    ):
        answer = await _ask(commanding, op, **params)
        assert answer["ok"], answer
        assert answer["result"]["request"][2:4] == function
        sent = [
            frame
            for frame in (await _ask(commanding, "trace"))["result"]["frames"]
            if frame["direction"] == "tx"
        ]
        assert len(sent) == 1

    @pytest.mark.asyncio
    async def test_the_octets_of_each_are_the_ones_pinned(self, commanding):
        assign = await _ask(commanding, "assign_class", event_class=3, points={"ai": [0, 1]})
        deadband = await _ask(commanding, "write_deadbands", variation=2, values={"4": 7, "5": 8})
        attribute = await _ask(commanding, "write_attribute", variation=240, value=1500)
        assert assign["result"]["request"][4:] == "3c04061e00000001"
        assert deadband["result"]["request"][4:] == "22020004050700000008000000"
        assert attribute["result"]["request"][4:] == "00f000000002" + "02dc05"

    @pytest.mark.asyncio
    async def test_a_command_above_the_level_is_refused_as_a_request_when_allowed(self, served):
        service = Service(allow_control=True)
        try:
            await service.handle(
                {
                    "op": "add",
                    "params": {
                        "name": "lab",
                        "host": "127.0.0.1",
                        "port": served.port,
                        "manual": True,
                        "level": 3,
                    },
                }
            )
            answer = await _ask(service, "write_deadbands", variation=1, values={"0": 1})
            assert answer["ok"] is False and answer["error"]["kind"] == "request"
            assert "Level 4 request" in answer["error"]["message"]
            assert (await _ask(service, "trace"))["result"]["frames"] == []
        finally:
            await service.close()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("op", "params", "says"),
        [
            ("assign_class", {"points": {"ai": [0]}}, "names an event class"),
            ("assign_class", {"event_class": 4, "points": {"ai": [0]}}, "4 is not an event class"),
            ("assign_class", {"event_class": 1}, "names points, by type"),
            ("assign_class", {"event_class": 1, "points": {"zz": [0]}}, "not a point type"),
            ("write_deadbands", {"variation": 1}, "names a variation and values"),
            ("write_deadbands", {"variation": 9, "values": {"0": 1}}, "not a deadband"),
            ("write_attribute", {"variation": 247}, "names its variation and its value"),
            ("write_attribute", {"variation": 241, "value": 1}, "cannot be written"),
        ],
    )
    async def test_what_is_wrong_is_said_before_the_permission_is_asked(
        self, reading, op, params, says
    ):
        # The service does not command: a refusal for being wrong comes first.
        answer = await _ask(reading, op, **params)
        assert answer["ok"] is False and answer["error"]["kind"] == "request"
        assert says in answer["error"]["message"]

    @pytest.mark.asyncio
    async def test_a_command_is_recorded_in_the_log_once_it_is_sent(self, commanding, caplog):
        caplog.set_level("INFO")
        await _ask(commanding, "write_attribute", variation=247, value="x")
        assert any(
            "command write_attribute to lab" in record.getMessage() for record in caplog.records
        )
