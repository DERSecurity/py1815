"""The checks of what a Level 3 and a Level 4 outstation answer.

Each check is run against a master that answers with octets written out by
hand, so that a response the standard allows passes and each way a response can
go wrong fails with what was wrong. The checks that need no more than what the
simulated DER already serves are also run against it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from profile_fixtures import document, paired_reference_der, row
from test_double_bit import Device

from py1815.application import FunctionCode, parse_response
from py1815.decode import decode_objects
from py1815.master import bench as benches
from py1815.master.association import Exchange, Outcome
from py1815.master.bench import Bench, Failed, NotApplicable, Unanswered, Verdict
from py1815.master.checks import SUBSET, SUBSET_CHECKS, select
from py1815.master.evaluate import evaluate_loopback
from py1815.master.loopback import Loopback
from py1815.master.profile import DerProfile
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.subset import SubsetLevel

LEVEL_2, LEVEL_3, LEVEL_4 = SubsetLevel.LEVEL_2, SubsetLevel.LEVEL_3, SubsetLevel.LEVEL_4

#: The indication bits that say the outstation did not take a request.
FUNC_NOT_SUPPORTED, OBJECT_UNKNOWN, PARAM_ERROR = 0x01, 0x02, 0x04

CHECKS = {check.id: check for check in SUBSET_CHECKS}


def _hex(text: str) -> bytes:
    return bytes.fromhex(text)


def answered(body: bytes = b"", second: int = 0, *, decoded: bytes | None = None) -> Exchange:
    """The exchange of a response carrying ``body``.

    Its objects are read from ``body``, or from ``decoded`` when that is given.
    """
    fragment = parse_response(bytes([0xC0, FunctionCode.RESPONSE, 0x00, second]) + body)
    read = decode_objects(body if decoded is None else decoded)
    return Exchange(
        FunctionCode.READ,
        0,
        b"",
        Outcome.COMPLETE,
        fragments=(fragment,),
        objects=read.objects,
        undecoded=() if read.complete else (read,),
    )


def silent() -> Exchange:
    return Exchange(FunctionCode.READ, 0, b"", Outcome.TIMEOUT)


class Master:
    """A master that records what it was asked and answers as it was told to."""

    def __init__(self, answers: dict[str, Exchange | Callable[..., Exchange]]) -> None:
        self.level = LEVEL_4
        self.answers = answers
        self.asked: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Callable[..., Exchange]:
        def ask(*args: Any, **kwargs: Any) -> Exchange:
            self.asked.append((name, args, kwargs))
            answer = self.answers[name]
            return answer(*args, **kwargs) if callable(answer) else answer

        return ask


@pytest.fixture(scope="module")
def points():
    return load.resolve(paired_reference_der(), Composition())


def _bench(points, *served: tuple[Kind, int]) -> Bench:
    bench = Bench(DerProfile(points))
    bench.served = frozenset(served)
    return bench


def run(check: str, master: Master, bench: Bench) -> Bench:
    """Carry out one check against a master, and return the bench that ran it."""
    benches.drive(master, CHECKS[check].procedure(bench), lambda _seconds: None)
    return bench


#: One analog input, point 4, as group 30 variation 1 carries it: online, 100.
AI_4 = _hex("1E 01 00 04 04 01 64 00 00 00")


class TestReadByVariation:
    def test_it_passes_when_the_point_comes_back(self, points):
        master = Master({"read_group": answered(decoded=AI_4)})
        run("LEVEL3-001", master, _bench(points, (Kind.AI, 4)))
        assert master.asked == [("read_group", (30, 1), {})]

    def test_it_reads_binary_inputs_by_variation_2_when_there_is_no_analog_input(self, points):
        master = Master(
            {"read_group": answered(decoded=_hex("01 02 00 07 07 81"))},
        )
        run("LEVEL3-001", master, _bench(points, (Kind.BI, 7), (Kind.CTR, 0)))
        assert master.asked == [("read_group", (1, 2), {})]

    def test_it_fails_when_the_point_is_missing(self, points):
        master = Master({"read_group": answered()})
        with pytest.raises(Failed, match="did not carry point 4"):
            run("LEVEL3-001", master, _bench(points, (Kind.AI, 4)))

    @pytest.mark.parametrize(
        ("second", "named"),
        [
            (FUNC_NOT_SUPPORTED, "FUNC_NOT_SUPPORTED"),
            (OBJECT_UNKNOWN, "OBJECT_UNKNOWN"),
            (PARAM_ERROR, "PARAM_ERROR"),
            (OBJECT_UNKNOWN | PARAM_ERROR, "OBJECT_UNKNOWN and PARAM_ERROR"),
        ],
    )
    def test_it_fails_when_the_outstation_says_it_did_not_take_the_request(
        self, points, second, named
    ):
        master = Master({"read_group": answered(second=second, decoded=AI_4)})
        with pytest.raises(Failed, match=f"with {named}"):
            run("LEVEL3-001", master, _bench(points, (Kind.AI, 4)))

    def test_it_fails_when_the_outstation_does_not_answer(self, points):
        with pytest.raises(Unanswered, match="did not answer a read of group 30 variation 1"):
            run("LEVEL3-001", Master({"read_group": silent()}), _bench(points, (Kind.AI, 4)))

    def test_it_is_not_applicable_when_no_point_of_a_kind_it_reads_is_served(self, points):
        with pytest.raises(NotApplicable):
            run("LEVEL3-001", Master({}), _bench(points, (Kind.AO, 4)))


class TestReadByRange:
    def test_it_asks_for_the_first_served_point_alone_and_passes_when_only_it_comes(self, points):
        master = Master({"read_group": answered(decoded=AI_4)})
        run("LEVEL3-002", master, _bench(points, (Kind.AI, 9), (Kind.AI, 4)))
        assert master.asked == [("read_group", (30,), {"start": 4, "stop": 4})]

    def test_it_fails_when_a_point_outside_the_range_comes_back(self, points):
        both = _hex("1E 01 00 04 05 01 64 00 00 00 01 65 00 00 00")
        master = Master({"read_group": answered(decoded=both)})
        with pytest.raises(Failed, match=r"carried points \[4, 5\]"):
            run("LEVEL3-002", master, _bench(points, (Kind.AI, 4)))

    def test_it_fails_when_nothing_comes_back(self, points):
        with pytest.raises(Failed, match=r"carried points \[\]"):
            run("LEVEL3-002", Master({"read_group": answered()}), _bench(points, (Kind.AI, 4)))


TIME = _hex("32 01 07 01 00 00 00 00 00 00")


class TestReadTime:
    def test_it_passes_for_one_object_of_group_50_variation_1(self, points):
        master = Master({"read_time": answered(TIME)})
        run("LEVEL3-003", master, _bench(points))
        assert master.asked == [("read_time", (), {})]

    @pytest.mark.parametrize(
        "body",
        [
            "",
            "32 01 07 01 00 00 00 00 00",
            "32 03 07 01 00 00 00 00 00 00",
            "32 01 07 02 " + "00" * 12,
        ],
    )
    def test_it_fails_for_any_other_answer(self, points, body):
        with pytest.raises(Failed, match="not one object of group 50 variation 1"):
            run("LEVEL3-003", Master({"read_time": answered(_hex(body))}), _bench(points))

    def test_it_fails_when_the_object_is_unknown(self, points):
        master = Master({"read_time": answered(second=OBJECT_UNKNOWN)})
        with pytest.raises(Failed, match="OBJECT_UNKNOWN"):
            run("LEVEL3-003", master, _bench(points))


class TestReadIndications:
    def test_it_passes_for_the_range_0_to_15_and_two_octets_of_bits(self, points):
        master = Master({"read_indications": answered(_hex("50 01 00 00 0F 00 00"))})
        run("LEVEL3-004", master, _bench(points))
        assert master.asked == [("read_indications", (), {})]

    @pytest.mark.parametrize("body", ["", "50 01 00 00 0F 00", "50 01 00 00 07 00 00"])
    def test_it_fails_for_any_other_answer(self, points, body):
        master = Master({"read_indications": answered(_hex(body))})
        with pytest.raises(Failed, match="not the range 0 to 15"):
            run("LEVEL3-004", master, _bench(points))


class TestAssignClass:
    @staticmethod
    def _assigned(points) -> tuple[int, int]:
        point = next(
            each
            for each in points.points.values()
            if each.kind is Kind.AI and each.event_class in (1, 2, 3)
        )
        return point.index, point.event_class

    def test_it_assigns_a_point_the_class_the_tables_give_it(self, points):
        index, event_class = self._assigned(points)
        master = Master({"assign_class": answered()})
        run("LEVEL3-005", master, _bench(points, (Kind.AI, index)))
        assert master.asked == [("assign_class", (event_class,), {"analog_inputs": [index]})]

    def test_it_fails_when_the_answer_carries_objects(self, points):
        index, _ = self._assigned(points)
        master = Master({"assign_class": answered(AI_4)})
        with pytest.raises(Failed, match="carried objects"):
            run("LEVEL3-005", master, _bench(points, (Kind.AI, index)))

    def test_it_fails_when_the_function_is_not_supported(self, points):
        index, _ = self._assigned(points)
        master = Master({"assign_class": answered(second=FUNC_NOT_SUPPORTED)})
        with pytest.raises(Failed, match="FUNC_NOT_SUPPORTED"):
            run("LEVEL3-005", master, _bench(points, (Kind.AI, index)))

    def test_it_writes_to_the_outstation_so_it_needs_the_run_to_be_allowed_to(self):
        assert CHECKS["LEVEL3-005"].commands
        assert not any(check.commands for check in SUBSET_CHECKS if check.id != "LEVEL3-005")

    def test_it_is_not_applicable_when_no_served_analog_input_has_a_class(self, points):
        with pytest.raises(NotApplicable, match="give a class"):
            run("LEVEL3-005", Master({}), _bench(points, (Kind.BI, 1)))


def _attribute(variation: int, kind: int, value: bytes) -> bytes:
    """One attribute of set 0: its header, data type code, length and value."""
    return bytes([0, variation, 0, 0, 0, kind, len(value)]) + value


NAME = _attribute(247, 1, b"ab")
MODEL = _attribute(250, 1, b"c")
#: The list: variation 249 and 250 each with a properties octet, as data type 254.
LISTED = _attribute(255, 254, bytes([249, 1, 250, 1]))


class TestDeviceAttributes:
    def test_every_attribute_is_read_with_no_range(self, points):
        master = Master({"read_attributes": answered(NAME + MODEL)})
        bench = run("LEVEL4-001", master, _bench(points))
        assert master.asked == [("read_attributes", (), {})]
        assert "2 attributes were returned" in bench.notes

    def test_a_response_of_attributes_with_ranges_of_16_bit_limits_is_read(self, points):
        wide = bytes([0, 247, 1, 0, 0, 0, 0, 1, 2]) + b"ab"
        run("LEVEL4-001", Master({"read_attributes": answered(wide)}), _bench(points))

    @pytest.mark.parametrize(
        ("body", "says"),
        [
            (b"", "carried no attributes"),
            (_attribute(254, 2, b"\x01"), "carried variation 254"),
            (NAME + LISTED, "carried variation 255"),
            (NAME[:-1], "could not be read: group 0 variation 247 is cut short"),
            (bytes([30, 1, 0, 0, 0]) + b"\x00" * 5, "carried group 30, not an attribute"),
            (NAME + bytes([0, 247, 6]), "could not be read: qualifier 0x06"),
        ],
    )
    def test_everything_else_fails(self, points, body, says):
        with pytest.raises(Failed, match=says):
            run("LEVEL4-001", Master({"read_attributes": answered(body)}), _bench(points))

    def test_the_list_is_read_and_each_attribute_it_names_is_read_by_variation(self, points):
        def reads(variation: int, *_rest: Any) -> Exchange:
            return answered(LISTED if variation == 255 else _attribute(variation, 1, b"x"))

        master = Master({"read_attributes": reads})
        bench = run("LEVEL4-002", master, _bench(points))
        assert master.asked == [
            ("read_attributes", (255,), {}),
            ("read_attributes", (249,), {}),
            ("read_attributes", (250,), {}),
        ]
        assert "2 attributes are listed" in bench.notes

    def test_a_list_names_the_attributes_but_not_the_list_itself(self, points):
        pairs = _attribute(255, 254, bytes([249, 1, 254, 0, 255, 0]))

        def reads(variation: int, *_rest: Any) -> Exchange:
            return answered(pairs if variation == 255 else _attribute(variation, 1, b"x"))

        master = Master({"read_attributes": reads})
        run("LEVEL4-002", master, _bench(points))
        assert [asked[1] for asked in master.asked] == [(255,), (249,)]

    def test_an_attribute_the_list_names_but_the_outstation_does_not_return_fails(self, points):
        def reads(variation: int, *_rest: Any) -> Exchange:
            if variation == 255:
                return answered(LISTED)
            return (
                answered(second=OBJECT_UNKNOWN)
                if variation == 250
                else answered(_attribute(variation, 1, b"x"))
            )

        with pytest.raises(Failed, match="attribute 250 with OBJECT_UNKNOWN"):
            run("LEVEL4-002", Master({"read_attributes": reads}), _bench(points))

    def test_an_attribute_that_comes_back_as_another_variation_fails(self, points):
        def reads(variation: int, *_rest: Any) -> Exchange:
            return answered(LISTED if variation == 255 else _attribute(248, 1, b"x"))

        with pytest.raises(Failed, match="which the list names, did not carry it"):
            run("LEVEL4-002", Master({"read_attributes": reads}), _bench(points))

    @pytest.mark.parametrize(
        ("body", "says"),
        [
            (b"", "carried no list"),
            (NAME, "carried no list"),
            (_attribute(255, 2, bytes([249])), "not pairs of octets"),
            (_attribute(255, 254, bytes([249, 1, 250])), "not pairs of octets"),
        ],
    )
    def test_a_list_that_is_not_pairs_fails(self, points, body, says):
        with pytest.raises(Failed, match=says):
            run("LEVEL4-002", Master({"read_attributes": answered(body)}), _bench(points))


class TestDeadbands:
    def test_it_passes_for_group_34_objects(self, points):
        master = Master({"read_deadbands": answered(_hex("22 01 00 04 04 0A 00"))})
        run("LEVEL4-003", master, _bench(points, (Kind.AI, 4)))
        assert master.asked == [("read_deadbands", (), {})]

    def test_it_passes_for_a_null_response(self, points):
        run("LEVEL4-003", Master({"read_deadbands": answered()}), _bench(points, (Kind.AI, 4)))

    def test_it_fails_when_another_group_comes_back(self, points):
        master = Master({"read_deadbands": answered(AI_4)})
        with pytest.raises(Failed, match="carried group 30"):
            run("LEVEL4-003", master, _bench(points, (Kind.AI, 4)))

    def test_it_fails_when_the_object_is_unknown(self, points):
        master = Master({"read_deadbands": answered(second=OBJECT_UNKNOWN)})
        with pytest.raises(Failed, match="OBJECT_UNKNOWN"):
            run("LEVEL4-003", master, _bench(points, (Kind.AI, 4)))

    def test_it_is_not_applicable_with_no_analog_input(self, points):
        with pytest.raises(NotApplicable):
            run("LEVEL4-003", Master({}), _bench(points, (Kind.BI, 1)))


class TestGroupsOnlyLevel4Defines:
    @pytest.mark.parametrize(
        ("check", "body"),
        [
            ("LEVEL4-004", "03 00 06 04 00 06"),
            ("LEVEL4-005", "0B 00 06 0D 00 06 2A 00 06 2B 00 06"),
        ],
    )
    def test_they_are_read_in_one_request_of_every_object_of_each(self, points, check, body):
        master = Master({"request": answered()})
        run(check, master, _bench(points, (Kind.DBI, 0)))
        assert master.asked == [("request", (FunctionCode.READ, _hex(body)), {})]

    @pytest.mark.parametrize("check", ["LEVEL4-004", "LEVEL4-005"])
    def test_they_fail_when_the_outstation_does_not_know_the_object(self, points, check):
        master = Master({"request": answered(second=OBJECT_UNKNOWN)})
        with pytest.raises(Failed, match="OBJECT_UNKNOWN"):
            run(check, master, _bench(points, (Kind.DBI, 0)))

    @pytest.mark.parametrize("check", ["LEVEL4-004", "LEVEL4-005"])
    def test_they_fail_when_another_group_comes_back(self, points, check):
        master = Master({"request": answered(AI_4)})
        with pytest.raises(Failed, match="carried group 30"):
            run(check, master, _bench(points, (Kind.DBI, 0)))

    @pytest.mark.parametrize("check", ["LEVEL4-004", "LEVEL4-005"])
    def test_they_fail_when_the_outstation_does_not_answer(self, points, check):
        with pytest.raises(Unanswered):
            run(check, Master({"request": silent()}), _bench(points, (Kind.DBI, 0)))

    def test_the_double_bit_check_does_not_apply_without_a_double_bit_input(self, points):
        with pytest.raises(NotApplicable, match="serves no double-bit input"):
            run("LEVEL4-004", Master({}), _bench(points, (Kind.BI, 1)))


class TestTheSet:
    def test_each_check_names_the_level_it_applies_from(self):
        levels = {check.id: check.level for check in SUBSET_CHECKS}
        assert {identifier for identifier, level in levels.items() if level is LEVEL_3} == {
            "LEVEL3-001",
            "LEVEL3-002",
            "LEVEL3-003",
            "LEVEL3-004",
            "LEVEL3-005",
        }
        assert {identifier for identifier, level in levels.items() if level is LEVEL_4} == {
            "LEVEL4-001",
            "LEVEL4-002",
            "LEVEL4-003",
            "LEVEL4-004",
            "LEVEL4-005",
        }

    def test_the_set_is_selected_by_its_name_and_no_other_check_is_in_it(self):
        assert select([SUBSET]) == SUBSET_CHECKS
        assert all(check.group == SUBSET for check in SUBSET_CHECKS)
        assert select(["level3-001"])[0].id == "LEVEL3-001"


# ------------------------------------------------- against the simulated DER


def _evaluate(level: SubsetLevel | None, checks=None, *, outstation: int | None = None):
    """Run checks with the master set to ``level`` against the DER held to ``outstation``.

    The outstation is held to the master's level unless ``outstation`` names
    another, and to no level when both are None.
    """
    points = load.resolve(paired_reference_der(), Composition())
    simulation = der.build(points, level=level if outstation is None else outstation)
    session = simulation.outstation.session(need_time=False)
    loopback = Loopback(session) if level is None else Loopback(session, level=level)
    report = evaluate_loopback(
        loopback,
        points,
        checks=select([SUBSET]) if checks is None else checks,
        commanding=True,
        advance=simulation.advance,
    )
    return {result.id: result for result in report.results}


class TestAgainstTheSimulatedDer:
    def test_at_level_2_no_check_of_the_set_applies_and_none_sends_a_request(self):
        for identifier, result in _evaluate(None).items():
            assert result.verdict is Verdict.NOT_APPLICABLE, identifier
            assert "set to Level 2" in result.detail and result.requests == 0
        assert "needs a Level 3 outstation" in _evaluate(LEVEL_2)["LEVEL3-001"].detail

    def test_at_level_3_the_level_4_checks_do_not_apply_and_the_reads_by_variation_pass(self):
        results = _evaluate(LEVEL_3)
        for identifier in ("LEVEL4-001", "LEVEL4-002", "LEVEL4-003", "LEVEL4-004", "LEVEL4-005"):
            assert results[identifier].verdict is Verdict.NOT_APPLICABLE
            assert "needs a Level 4 outstation" in results[identifier].detail
            assert "set to Level 3" in results[identifier].detail
        assert results["LEVEL3-001"].verdict is Verdict.PASSED
        assert results["LEVEL3-002"].verdict is Verdict.PASSED
        assert results["LEVEL3-001"].requests == 1

    def test_at_level_3_every_level_3_check_passes(self):
        for identifier, result in _evaluate(LEVEL_3).items():
            if identifier.startswith("LEVEL3-"):
                assert result.verdict is Verdict.PASSED, (identifier, result.detail)

    def test_at_level_4_every_check_applies_and_passes(self):
        for identifier, result in _evaluate(LEVEL_4).items():
            if identifier == "LEVEL4-004":
                # The simulated DER has no double-bit input.
                assert result.verdict is Verdict.NOT_APPLICABLE
                assert "serves no double-bit input" in result.detail
            else:
                assert result.verdict is Verdict.PASSED, (identifier, result.detail)

    def test_at_level_4_double_bit_inputs_and_their_events_are_read(self):
        device = Device(level=4)
        loopback = Loopback(device.session, clock=device.clock, level=LEVEL_4)
        tables = document(
            {"BI": [row("Alarm", 0, event_class=1)], "DBI": [row("Valve 0", 0, event_class=1)]}
        )
        report = evaluate_loopback(
            loopback, load.resolve(tables, Composition()), checks=select(["LEVEL4-004"])
        )
        (result,) = report.results
        assert result.verdict is Verdict.PASSED, result.detail

    def test_a_master_set_above_the_outstation_fails_the_checks_the_outstation_lacks(self):
        # The master is set to Level 4 and the outstation is held to Level 2.
        # What Level 2 serves passes; what only Level 3 and 4 serve fails with
        # the indication the outstation answered with.
        results = _evaluate(LEVEL_4, outstation=2)
        for identifier in ("LEVEL3-003", "LEVEL3-004", "LEVEL3-005"):
            assert results[identifier].verdict is Verdict.FAILED, identifier
        for identifier in ("LEVEL4-001", "LEVEL4-002", "LEVEL4-003", "LEVEL4-005"):
            assert results[identifier].verdict is Verdict.FAILED, identifier
            assert "OBJECT_UNKNOWN" in results[identifier].detail, identifier

    def test_a_run_not_allowed_to_write_leaves_the_assignment_unsent(self):
        simulation = der.build(load.resolve(paired_reference_der(), Composition()))
        loopback = Loopback(simulation.outstation.session(need_time=False), level=LEVEL_3)
        points = load.resolve(paired_reference_der(), Composition())
        report = evaluate_loopback(
            loopback, points, checks=select(["LEVEL3-005"]), commanding=False
        )
        (result,) = report.results
        assert result.verdict is Verdict.NOT_RUN and result.requests == 0
        assert "writes to the outstation" in result.detail
