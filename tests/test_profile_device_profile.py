"""The generated DNP3 Device Profile says what the outstation does, and nothing else.

The document is a set of claims: these points, these limits, these objects and
function codes. Most of this file sends the session what the implementation
table says it accepts, and what the table leaves out, and checks the session
agrees in both directions, so the table cannot drift from the behavior it
describes. Validation against the Users Group schema runs where a checkout
has a copy of it, since the schema may not be redistributed.
"""

from __future__ import annotations

import datetime
import pathlib
import struct
from typing import ClassVar
from xml.etree import ElementTree

import pytest
from profile_fixtures import REAL_TABLES, for_reference_der, small, units

from py1815.application import FunctionCode, IIN2Bit
from py1815.control import CommandStatus, ControlRelayOutputBlock, OperationType, encode_crob
from py1815.objects import AnalogEventVariation
from py1815.profile import cli, der, device_profile, load
from py1815.profile.binding import Binding
from py1815.profile.device_profile import NAMESPACE, Identity, Row
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation
from py1815.profile.probe import parse_objects
from py1815.session import Session

SCHEMA = pathlib.Path(__file__).resolve().parent.parent / "schema" / device_profile.SCHEMA_FILE
NS = {"d": NAMESPACE}
REFUSALS = IIN2Bit.FUNC_NOT_SUPPORTED | IIN2Bit.OBJECT_UNKNOWN | IIN2Bit.PARAM_ERROR

#: The kind of point each static or command group addresses.
GROUP_KIND = {1: Kind.BI, 10: Kind.BO, 12: Kind.BO, 20: Kind.CTR, 21: Kind.CTR}
GROUP_KIND |= {30: Kind.AI, 40: Kind.AO, 41: Kind.AO}


@pytest.fixture
def simulation() -> der.Simulation:
    built = der.build(load.resolve(for_reference_der(), Composition()))
    # Give every event group something to report.
    built.advance(5.0)
    built.der.started = False
    built.advance(5.0)
    return built


def _document(simulation: der.Simulation, **session_options) -> ElementTree.Element:
    session = simulation.outstation.session(**session_options)
    return device_profile.build(
        simulation.outstation,
        session,
        Identity(vendor="Example", host="192.0.2.1", port=20000),
        today=datetime.date(2026, 1, 2),
    )


def _text(root: ElementTree.Element, path: str) -> str | None:
    found = root.find(path, NS)
    return None if found is None else found.text


class Sender:
    """Sends application fragments to one session under advancing sequence numbers."""

    def __init__(self, session) -> None:
        self.session = session
        self.sequence = 0

    def send(self, function: int, body: bytes = b"") -> bytes:
        fragment = bytes([0xC0 | self.sequence, function]) + body
        self.sequence = (self.sequence + 1) % 16
        return self.session._handle_fragment(fragment)


def _index(outstation: DerOutstation, group: int) -> int:
    kind = GROUP_KIND[group]
    if kind is Kind.AO:
        return der.AO_POWER_LIMIT_MAXIMUM
    if kind is Kind.BO:
        return der.BO_PERMIT_STOP
    return outstation.served(kind)[0].index


def _read_header(outstation: DerOutstation, row: Row, qualifier: int) -> bytes:
    """One read header for a row, in the qualifier asked for."""
    head = bytes([row.group, row.variation, qualifier])
    if qualifier == 0x06:
        return head
    if qualifier == 0x07:
        return head + bytes([1])
    if qualifier == 0x08:
        return head + struct.pack("<H", 1)
    index = _index(outstation, row.group)
    if qualifier == 0x17:
        return head + bytes([1, index])
    if qualifier == 0x28:
        return head + struct.pack("<HH", 1, index)
    return head + (bytes([index, index]) if qualifier == 0x00 else struct.pack("<HH", index, index))


def _command(outstation: DerOutstation, row: Row, qualifier: int) -> bytes:
    """One control object for a row, behind its index, in the qualifier asked for."""
    index = _index(outstation, row.group)
    if row.group == 12:
        payload = encode_crob(ControlRelayOutputBlock.build(OperationType.LATCH_ON))
    else:
        fmt = {1: "<i", 2: "<h", 3: "<f", 4: "<d"}[row.variation]
        payload = struct.pack(fmt, 50) + b"\x00"
    prefix = bytes([1, index]) if qualifier == 0x17 else struct.pack("<HH", 1, index)
    return bytes([row.group, row.variation, qualifier]) + prefix + payload


def _refused(response: bytes) -> int:
    return response[3] & REFUSALS


class TestEveryRequestTheTableListsIsAnswered:
    """Each row's request, in each qualifier it names, sent to the real session."""

    def _rows(self, simulation, functions):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        rows = [r for r in table.rows if r.request and r.request[0] in functions]
        assert rows, "the table lists nothing for these functions"
        return Sender(session), rows

    def test_reads(self, simulation):
        sender, rows = self._rows(simulation, {device_profile.READ})
        for row in rows:
            for qualifier in row.request[1]:
                response = sender.send(1, _read_header(simulation.outstation, row, qualifier))
                assert not _refused(response), (row, hex(qualifier))

    def test_writes(self, simulation):
        sender, rows = self._rows(simulation, {device_profile.WRITE})
        assert {(row.group, row.variation) for row in rows} == {(50, 1), (50, 3), (80, 1)}
        for row in rows:
            for qualifier in row.request[1]:
                if row.group == 50:
                    if row.variation == 3:
                        # The last recorded time is written after asking for one to be recorded.
                        assert not _refused(sender.send(FunctionCode.RECORD_CURRENT_TIME))
                    moment = (1_700_000_000_000).to_bytes(6, "little")
                    body = bytes([50, row.variation, qualifier, 1]) + moment
                else:
                    span = bytes([7, 7]) if qualifier == 0x00 else struct.pack("<HH", 7, 7)
                    body = bytes([80, 1, qualifier]) + span + b"\x00"
                assert not _refused(sender.send(2, body)), (row, hex(qualifier))

    def test_selects_operates_and_direct_operates(self, simulation):
        sender, rows = self._rows(
            simulation, {device_profile.SELECT, device_profile.OPERATE, device_profile.DIRECT}
        )
        for row in rows:
            for qualifier in row.request[1]:
                body = _command(simulation.outstation, row, qualifier)
                if row.request[0] == device_profile.OPERATE:
                    sender.send(device_profile.SELECT, body)
                response = sender.send(row.request[0], body)
                assert not _refused(response), (row, hex(qualifier))
                assert CommandStatus(response[-1]) is CommandStatus.SUCCESS, (row, hex(qualifier))
                assert response[6] in row.response[1], "the echo uses a qualifier the row lists"

    def test_requests_that_take_no_response_draw_none(self, simulation):
        sender, rows = self._rows(
            simulation,
            {device_profile.DIRECT_NR, device_profile.FREEZE_NR, device_profile.FREEZE_CLEAR_NR},
        )
        for row in rows:
            assert row.response is None
            for qualifier in row.request[1]:
                if row.group == 20:
                    body = _read_header(simulation.outstation, row, qualifier)
                else:
                    body = _command(simulation.outstation, row, qualifier)
                assert sender.send(row.request[0], body) == b"", (row, hex(qualifier))

    def test_a_no_response_direct_operate_still_operates(self, simulation):
        """Silence is the answer, not the outcome."""
        sender, _ = self._rows(simulation, {device_profile.DIRECT_NR})
        row = Row(41, 1, "", request=(device_profile.DIRECT_NR, (0x17,)))
        sender.send(device_profile.DIRECT_NR, _command(simulation.outstation, row, 0x17))
        assert simulation.outstation.value(Kind.AO, der.AO_POWER_LIMIT_MAXIMUM) == 50

    def test_freezes(self, simulation):
        sender, rows = self._rows(simulation, {device_profile.FREEZE, device_profile.FREEZE_CLEAR})
        for row in rows:
            for qualifier in row.request[1]:
                response = sender.send(
                    row.request[0], _read_header(simulation.outstation, row, qualifier)
                )
                assert len(response) == 4 and not _refused(response), (row, hex(qualifier))

    def test_function_codes_that_carry_no_object(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        sender = Sender(session)
        assert set(table.function_codes) == {0, 21, 23, 24}
        assert sender.send(FunctionCode.CONFIRM) == b""
        assert not _refused(sender.send(FunctionCode.DISABLE_UNSOLICITED, bytes([60, 2, 6])))
        assert not _refused(sender.send(FunctionCode.DELAY_MEASURE))
        assert not _refused(sender.send(FunctionCode.RECORD_CURRENT_TIME))


class TestEveryResponseTheTableListsIsWhatIsSent:
    def test_a_named_variation_is_answered_in_that_variation(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        sender = Sender(session)
        rows = [r for r in table.rows if r.response and r.request and r.request[0] == 1]
        assert len(rows) > 10
        for row in rows:
            response = sender.send(1, bytes([row.group, row.variation, 0x06]))
            body = response[4:]
            if (row.group, row.variation) == (2, 3):
                # Relative times count from a common time, which comes first.
                assert body[0] == 51 and (51, body[1]) in {
                    (r.group, r.variation) for r in table.rows
                }
                body = body[10:]
            assert tuple(body[:2]) == (row.group, row.variation), row
            assert body[2] in row.response[1], (row, "qualifier", hex(body[2]))

    def test_variation_zero_is_answered_in_a_variation_the_table_lists(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        sender = Sender(session)
        listed = {(r.group, r.variation) for r in table.rows if r.response}
        any_variation = [r for r in table.rows if r.variation == 0 and r.request[0] == 1]
        answered = 0
        for row in any_variation:
            response = sender.send(1, bytes([row.group, 0, 0x06]))
            if len(response) > 4:
                assert (response[4], response[5]) in listed, row
                answered += 1
        assert answered >= 8, "the fixture gave most groups something to report"

    def test_an_integrity_poll_carries_only_listed_objects(self, simulation):
        session = simulation.outstation.session(max_response=8192)
        table = device_profile.implementation(simulation.outstation, session.facts)
        listed = {(r.group, r.variation) for r in table.rows if r.response}
        body = b"".join(bytes([60, v, 0x06]) for v in (2, 3, 4, 1))
        response = Sender(session).send(1, body)
        static, events = parse_objects(response[4:])
        seen = {(value.group, value.variation) for value in (*static, *events)}
        assert seen and seen <= listed, seen - listed

    def test_the_delay_measurement_answer_is_the_listed_object(self, simulation):
        response = Sender(simulation.outstation.session()).send(FunctionCode.DELAY_MEASURE)
        assert tuple(response[4:7]) == (52, 2, 0x07)


class TestWhatTheTableLeavesOutIsRefused:
    def test_every_other_function_code_is_refused_or_met_with_silence(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        listed = {r.request[0] for r in table.rows if r.request} | set(table.function_codes)
        sender = Sender(session)
        checked = 0
        for function in range(0, 0x22):
            if function in listed:
                continue
            response = sender.send(function)
            assert response == b"" or response[3] & IIN2Bit.FUNC_NOT_SUPPORTED, function
            checked += 1
        assert checked > 15

    def test_an_unlisted_variation_of_a_listed_group_is_an_unknown_object(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        readable = {(r.group, r.variation) for r in table.rows if r.request and r.request[0] == 1}
        sender = Sender(session)
        checked = 0
        for group in sorted({group for group, _ in readable} - {60}):
            for variation in range(1, 11):
                if (group, variation) in readable:
                    continue
                response = sender.send(1, bytes([group, variation, 0x06]))
                assert response[3] & IIN2Bit.OBJECT_UNKNOWN, (group, variation)
                checked += 1
        assert checked > 40

    @pytest.mark.parametrize("group", [3, 4, 11, 13, 31, 33, 42, 43, 70, 110])
    def test_an_unlisted_group_is_an_unknown_object(self, simulation, group):
        response = Sender(simulation.outstation.session()).send(1, bytes([group, 0, 0x06]))
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN


def _monitor() -> tuple[DerOutstation, Binding]:
    """An outstation with inputs only: no outputs, no counters."""
    binding = Binding()
    binding.read(Kind.BI, 0, lambda: False)
    binding.read(Kind.AI, 1, lambda: 5.0)
    return DerOutstation(load.resolve(small(), units(0)), binding, strict=False), binding


class TestTheTableFollowsTheConfiguration:
    def test_a_monitor_lists_no_outputs_controls_counters_or_freezes(self):
        outstation, _ = _monitor()
        table = device_profile.implementation(outstation, outstation.session().facts)
        groups = {row.group for row in table.rows}
        assert not groups & {10, 12, 20, 21, 22, 23, 40, 41}
        functions = {row.request[0] for row in table.rows if row.request}
        assert functions == {device_profile.READ, device_profile.WRITE}

    def test_and_the_session_refuses_what_it_does_not_list(self):
        """The control for the table: a monitor really does refuse a control."""
        outstation, _ = _monitor()
        row = Row(41, 1, "", request=(device_profile.DIRECT, (0x17,)))
        body = bytes([41, 1, 0x17, 1, 0]) + struct.pack("<i", 1) + b"\x00"
        response = Sender(outstation.session()).send(row.request[0], body)
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_outputs_served_by_a_session_given_no_control_provider_list_no_controls(
        self, simulation
    ):
        """What is listed follows the session serving the points, not the points alone."""
        outstation = simulation.outstation
        session = Session(outstation, events=outstation.events)
        table = device_profile.implementation(outstation, session.facts)
        groups = {row.group for row in table.rows}
        assert 10 in groups and 40 in groups, "the status is still readable"
        assert not groups & {12, 41}
        body = _command(outstation, Row(41, 1, ""), 0x17)
        response = Sender(session).send(device_profile.DIRECT, body)
        assert response[3] & IIN2Bit.OBJECT_UNKNOWN

    def test_counters_served_by_a_session_given_no_freeze_provider_list_no_freezes(
        self, simulation
    ):
        outstation = simulation.outstation
        session = Session(outstation, events=outstation.events)
        table = device_profile.implementation(outstation, session.facts)
        functions = {row.request[0] for row in table.rows if row.request}
        assert not functions & {7, 8, 9, 10}
        assert 20 in {row.group for row in table.rows}
        response = Sender(session).send(device_profile.FREEZE, bytes([20, 0, 0x06]))
        assert response[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_the_default_analog_event_variation_is_the_one_the_session_reports(self, simulation):
        session = simulation.outstation.session(
            analog_event_variation=AnalogEventVariation.INT16_WITH_TIME
        )
        root = device_profile.build(simulation.outstation, session)
        default = root.find(
            "d:referenceDevice/d:database/d:analogInputGroup/d:configuration/"
            "d:defaultEventVariation/d:currentValue/d:four",
            NS,
        )
        assert default is not None
        response = Sender(session).send(1, bytes([60, 3, 0x06]))
        assert tuple(response[4:6]) == (32, 4)

    def test_a_level_2_outstation_lists_and_sends_level_2_objects(self):
        """Frozen counters without time, analog output status in 16 bits, no frozen events."""
        point_map = load.resolve(for_reference_der(), Composition())
        device = der.ReferenceDer()
        outstation = DerOutstation(point_map, device.bind(point_map), level2=True)
        outstation.freeze_all()
        session = outstation.session()
        table = device_profile.implementation(outstation, session.facts)
        listed = {(row.group, row.variation) for row in table.rows if row.response}
        assert (23, 5) not in listed and (23, 1) not in listed
        sender = Sender(session)
        assert tuple(sender.send(1, bytes([21, 0, 0x06]))[4:6]) == (21, 1)
        assert tuple(sender.send(1, bytes([40, 0, 0x06]))[4:6]) == (40, 2)
        assert sender.send(1, bytes([60, 4, 0x06]))[4:] == b"", "the freeze buffered no event"
        root = device_profile.build(outstation, session)
        base = "d:referenceDevice/d:database/"
        assert (
            root.find(
                base + "d:counterGroup/d:configuration/d:defaultFrozenCounterStaticVariation/"
                "d:currentValue/d:one",
                NS,
            )
            is not None
        )
        assert (
            root.find(
                base + "d:analogOutputGroup/d:configuration/d:defaultStaticVariation/"
                "d:currentValue/d:two",
                NS,
            )
            is not None
        )


class TestConfigurationIsReadFromTheSession:
    def test_addresses_and_fragment_sizes(self, simulation):
        root = _document(
            simulation,
            outstation_address=77,
            master_address=9,
            max_response=4096,
            max_fragment=1500,
        )
        base = "d:referenceDevice/d:configuration/"
        assert _text(root, base + "d:linkConfig/d:dataLinkAddress/d:currentValue/d:value") == "77"
        assert (
            _text(root, base + "d:linkConfig/d:expectedSourceAddress/d:currentValue/d:value") == "9"
        )
        application = base + "d:applConfig/"
        assert (
            _text(root, application + "d:maxTransmittedFragmentSize/d:currentValue/d:value")
            == "4096"
        )
        assert (
            _text(root, application + "d:maxReceivedFragmentSize/d:currentValue/d:value") == "1500"
        )

    def test_the_select_timeout(self, simulation):
        root = _document(simulation, select_timeout=30.0)
        path = (
            "d:referenceDevice/d:database/d:analogOutputGroup/d:configuration/"
            "d:maxTimeBetweenSelectAndOperate/d:currentValue/d:value"
        )
        assert _text(root, path) == "30"

    def test_whether_the_time_is_asked_for(self, simulation):
        path = (
            "d:referenceDevice/d:configuration/d:outstationPerformance/"
            "d:outstationSetsIIN14/d:currentValue/"
        )
        assert _document(simulation).find(path + "d:atStartup", NS) is not None
        assert _document(simulation, need_time=False).find(path + "d:never", NS) is not None

    def test_the_event_buffer_size(self, simulation):
        path = (
            "d:referenceDevice/d:configuration/d:outstationConfig/"
            "d:eventBufferOrganization/d:currentValue/d:perClass/d:class2Value"
        )
        assert _text(_document(simulation), path) == str(simulation.outstation.events.capacity)

    def test_identity_and_where_it_listens(self, simulation):
        root = _document(simulation)
        base = "d:referenceDevice/d:configuration/"
        assert _text(root, base + "d:deviceConfig/d:vendorName/d:currentValue/d:value") == "Example"
        assert (
            _text(root, base + "d:networkConfig/d:ipAddress/d:currentValue/d:address")
            == "192.0.2.1"
        )
        assert (
            _text(root, base + "d:networkConfig/d:tcpListenPort/d:currentValue/d:value") == "20000"
        )

    def test_command_statuses_include_the_bindings_own(self, simulation):
        session = simulation.outstation.session()
        root = device_profile.build(
            simulation.outstation, session, statuses=[CommandStatus.BLOCKED]
        )
        codes = root.find(
            "d:referenceDevice/d:configuration/d:applConfig/"
            "d:controlStatusCodesSupported/d:capabilities",
            NS,
        )
        names = {child.tag.split("}")[1] for child in codes}
        assert names == {"code1", "code2", "code3", "code4", "code12", "code15"}


class TestThePointLists:
    PATHS: ClassVar[dict[Kind, str]] = {
        Kind.BI: "d:binaryInputPoints/d:dataPoints/d:binaryInput",
        Kind.BO: "d:binaryOutputPoints/d:dataPoints/d:binaryOutput",
        Kind.CTR: "d:counterPoints/d:dataPoints/d:counter",
        Kind.AI: "d:analogInputPoints/d:dataPoints/d:analogInput",
        Kind.AO: "d:analogOutputPoints/d:dataPoints/d:analogOutput",
    }

    @pytest.mark.parametrize("kind", list(Kind))
    def test_every_served_point_is_listed_and_no_other(self, simulation, kind):
        root = _document(simulation)
        listed = [
            int(point.find("d:index", NS).text)
            for point in root.findall("d:referenceDevice/d:dataPointsList/" + self.PATHS[kind], NS)
        ]
        assert listed == [point.index for point in simulation.outstation.served(kind)]
        assert listed

    def test_a_monitor_has_no_output_lists_at_all(self):
        outstation, _ = _monitor()
        root = device_profile.build(outstation, outstation.session())
        lists = root.find("d:referenceDevice/d:dataPointsList", NS)
        assert {child.tag.split("}")[1] for child in lists} == {
            "binaryInputPoints",
            "analogInputPoints",
        }
        assert root.find(".//d:controlStatusCodesSupported", NS) is None

    def _small(self, policy=None, deadband: float | None = None) -> ElementTree.Element:
        binding = Binding()
        binding.read(Kind.BI, 0, lambda: False)
        binding.read(Kind.AI, 1, lambda: 1.0, deadband=deadband)
        binding.read(Kind.AI, 2, lambda: 240.0)
        binding.read(Kind.AI, 4, lambda: 7.0)
        binding.read(Kind.CTR, 0, lambda: 1)
        binding.read(Kind.CTR, 5, lambda: 1)
        binding.output(Kind.BO, 0)
        binding.output(Kind.AO, 0)
        outstation = DerOutstation(
            load.resolve(small(), units(0)), binding, strict=False, event_policy=policy
        )
        return device_profile.build(outstation, outstation.session())

    def _point(self, root, kind: Kind, index: int) -> ElementTree.Element:
        for point in root.findall("d:referenceDevice/d:dataPointsList/" + self.PATHS[kind], NS):
            if point.find("d:index", NS).text == str(index):
                return point
        raise AssertionError(f"{kind.value}{index} is not listed")

    def test_scaling_range_and_units_come_from_the_map(self):
        voltage = self._point(self._small(), Kind.AI, 2)
        assert _text(voltage, "d:scaleFactor") == "0.1"
        assert _text(voltage, "d:minIntegerTransmittedValue") == "0"
        assert _text(voltage, "d:maxIntegerTransmittedValue") == "6000"
        assert _text(voltage, "d:units") == "x"

    def test_event_class_and_class_0_membership(self):
        root = self._small()
        assert _text(self._point(root, Kind.BI, 0), "d:changeEventClass") == "one"
        assert _text(self._point(root, Kind.BI, 1), "d:changeEventClass") == "none"
        advertised = self._point(root, Kind.AI, 65000)
        assert _text(advertised, "d:includedInClass0Response") == "never"
        assert _text(self._point(root, Kind.AI, 2), "d:includedInClass0Response") == "always"

    def test_the_event_class_listed_is_the_one_an_event_policy_put_in_force(self):
        policy = {
            "defaults": {"BI": {"events": False}},
            "points": {"AI2": {"class": 1}, "AI4": {"class": 3}, "CTR0": {"class": 2}},
        }
        root = self._small(policy)
        alarm = self._point(root, Kind.BI, 0)
        assert _text(alarm, "d:changeEventClass") == "none"
        assert _text(alarm, "d:includedInClass0Response") == "always", "off is not absent"
        assert _text(self._point(root, Kind.AI, 2), "d:changeEventClass") == "one"
        assert _text(self._point(root, Kind.AI, 4), "d:changeEventClass") == "three"
        assert _text(self._point(root, Kind.AI, 1), "d:changeEventClass") == "three", "untouched"
        assert _text(self._point(root, Kind.CTR, 0), "d:frozenCounterEventClass") == "two"

    def test_a_counter_whose_freezes_log_no_event_says_so(self):
        root = self._small({"points": {"CTR0": {"events": False}}})
        counter = self._point(root, Kind.CTR, 0)
        assert _text(counter, "d:frozenCounterExists") == "true"
        assert _text(counter, "d:frozenCounterEventClass") == "none"

    def test_the_deadband_listed_is_the_one_in_force_in_transmitted_units(self):
        root = self._small({"points": {"AI2": {"deadband": 2.0}}}, deadband=15)
        assert _text(self._point(root, Kind.AI, 2), "d:dnpData/d:deadband") == "20", (
            "two volts at a multiplier of 0.1"
        )
        assert _text(self._point(root, Kind.AI, 1), "d:dnpData/d:deadband") == "15", (
            "what the binding gave, which is transmitted units already"
        )

    def test_a_point_with_no_deadband_lists_zero_and_one_with_no_events_lists_none(self):
        root = self._small()
        assert _text(self._point(root, Kind.AI, 2), "d:dnpData/d:deadband") == "0"
        assert self._point(root, Kind.AI, 4).find("d:dnpData", NS) is None
        off = self._small({"points": {"AI2": {"events": False}}})
        assert self._point(off, Kind.AI, 2).find("d:dnpData", NS) is None

    def test_the_document_and_the_wire_agree_on_the_class(self):
        """The control for the list: an event arrives in the class the document names."""
        level = [240.0]
        binding = Binding()
        binding.read(Kind.AI, 2, lambda: level[0])
        policy = {"points": {"AI2": {"class": 1}}}
        outstation = DerOutstation(
            load.resolve(small(), units(0)), binding, strict=False, event_policy=policy
        )
        session = outstation.session()
        root = device_profile.build(outstation, session)
        assert _text(self._point(root, Kind.AI, 2), "d:changeEventClass") == "one"
        outstation.poll()
        level[0] = 250.0
        outstation.poll()
        _, events = parse_objects(Sender(session).send(1, bytes([60, 2, 0x06]))[4:])
        assert [(event.group, event.index) for event in events] == [(32, 2)]

    def test_a_group_with_points_in_and_out_of_class_0_says_it_depends_on_the_point(self):
        mode = self._small().find(
            "d:referenceDevice/d:database/d:analogInputGroup/d:configuration/"
            "d:analogInputClass0ResponseMode/d:currentValue/d:basedOnPointIndex",
            NS,
        )
        assert mode is not None

    def test_a_counter_says_whether_it_has_a_frozen_twin(self):
        root = self._small()
        assert _text(self._point(root, Kind.CTR, 0), "d:frozenCounterExists") == "true"
        assert _text(self._point(root, Kind.CTR, 5), "d:frozenCounterExists") == "false"
        assert self._point(root, Kind.CTR, 5).find("d:frozenCounterEventClass", NS) is None

    def test_outputs_list_the_operations_the_builder_accepts(self):
        root = self._small()
        binary = self._point(root, Kind.BO, 0).find("d:supportedControlOperations", NS)
        assert {c.tag.split("}")[1] for c in binary} >= {"supportLatchOn", "supportTrip"}
        analog = self._point(root, Kind.AO, 0)
        assert _text(analog, "d:minTransmittedValue") == "-1000"

    def test_a_long_name_becomes_a_name_and_a_description(self):
        tables = small()
        tables["points"]["BI"][0]["name"] = "Alarm. Raised when the widget is out of range."
        binding = Binding()
        binding.read(Kind.BI, 0, lambda: False)
        outstation = DerOutstation(load.resolve(tables, units(0)), binding, strict=False)
        point = self._point(device_profile.build(outstation, outstation.session()), Kind.BI, 0)
        assert _text(point, "d:name") == "Alarm"
        assert _text(point, "d:description") == "Alarm. Raised when the widget is out of range."


class TestWhatIsNotClaimed:
    def test_nothing_that_would_need_measuring_or_certifying(self, simulation):
        root = _document(simulation)
        for name in (
            "conformanceTesting",
            "maxTimeBaseDrift",
            "responseTime",
            "delayMeasurementError",
            "binaryOrDoubleBitEventError",
            "securityConfig",
            "broadcastConfig",
        ):
            assert root.find(f".//d:{name}", NS) is None, name

    def test_unsolicited_reporting_is_stated_as_not_supported(self, simulation):
        root = _document(simulation)
        base = (
            "d:referenceDevice/d:configuration/d:unsolicitedConfig/d:supportsUnsolicitedReporting/"
        )
        assert root.find(base + "d:capabilities/d:supported/d:no", NS) is not None
        assert root.find(base + "d:currentValue/d:off", NS) is not None

    def test_the_level_claimed_is_two(self, simulation):
        level = _document(simulation).find(
            "d:referenceDevice/d:configuration/d:deviceConfig/d:dnpLevelSupported/"
            "d:currentValue/d:outStation",
            NS,
        )
        assert [child.tag.split("}")[1] for child in level] == ["level2"]


class TestTheDocumentItself:
    def test_it_names_the_schema_edition_and_namespace(self, simulation):
        root = _document(simulation)
        assert root.tag == f"{{{NAMESPACE}}}DNP3DeviceProfileDocument"
        assert root.get("schemaVersion") == "2.12.00"
        location = root.get("{http://www.w3.org/2001/XMLSchema-instance}schemaLocation")
        assert location == f"{NAMESPACE} {device_profile.SCHEMA_FILE}"

    def test_the_text_declares_itself_and_points_at_the_stylesheet(self, simulation):
        text = device_profile.render(_document(simulation))
        first, second, third = text.splitlines()[:3]
        assert first == '<?xml version="1.0" encoding="UTF-8"?>'
        assert (
            second == f'<?xml-stylesheet type="text/xsl" href="{device_profile.STYLESHEET_FILE}"?>'
        )
        assert third.startswith(f'<DNP3DeviceProfileDocument xmlns="{NAMESPACE}"')
        ElementTree.fromstring(text.split("?>", 2)[2])

    def test_two_builds_of_one_outstation_are_identical(self, simulation):
        """Nothing in it depends on when it was run but the date it is given."""
        assert device_profile.render(_document(simulation)) == device_profile.render(
            _document(simulation)
        )

    def test_the_date_is_the_one_given(self, simulation):
        assert _text(_document(simulation), "d:documentHeader/d:revisionHistory/d:date") == (
            "2026-01-02"
        )

    def test_the_software_version_defaults_to_the_librarys(self):
        assert Identity().software().startswith("py1815")
        assert Identity(software_version="4.2").software() == "4.2"


def _validate(root: ElementTree.Element) -> list:
    xmlschema = pytest.importorskip("xmlschema")
    return list(xmlschema.XMLSchema(str(SCHEMA)).iter_errors(device_profile.render(root)))


@pytest.mark.skipif(not SCHEMA.is_file(), reason="the Users Group schema is obtained locally")
class TestAgainstTheSchema:
    def test_the_simulated_der_validates(self, simulation):
        assert _validate(_document(simulation)) == []

    def test_a_monitor_validates(self):
        outstation, _ = _monitor()
        assert _validate(device_profile.build(outstation, outstation.session())) == []

    def test_an_outstation_under_an_event_policy_validates(self):
        binding = Binding()
        binding.read(Kind.BI, 0, lambda: False)
        binding.read(Kind.AI, 2, lambda: 240.0)
        binding.read(Kind.CTR, 0, lambda: 1)
        policy = {
            "defaults": {"BI": {"events": False}},
            "points": {"AI2": {"class": 1, "deadband": 0.25}, "CTR0": {"class": 2}},
        }
        outstation = DerOutstation(
            load.resolve(small(), units(0)), binding, strict=False, event_policy=policy
        )
        assert _validate(device_profile.build(outstation, outstation.session())) == []

    def test_a_document_in_the_wrong_order_does_not(self, simulation):
        """The control: the validator is one that can say no."""
        root = _document(simulation)
        header = root.find("d:documentHeader", NS)
        header.append(header[0])
        header.remove(header[0])
        assert _validate(root)

    @pytest.mark.skipif(not REAL_TABLES.is_file(), reason="the IEEE tables are generated locally")
    def test_the_profile_for_the_real_point_map_validates(self):
        built = der.build(load.load(REAL_TABLES, Composition(meters=1, inverters=1)))
        root = device_profile.build(built.outstation, built.outstation.session())
        assert _validate(root) == []


class TestTheCommand:
    @pytest.fixture
    def tables(self, tmp_path, monkeypatch):
        import json

        path = tmp_path / load.TABLES_NAME
        path.write_text(json.dumps(for_reference_der()), encoding="utf-8")
        monkeypatch.setenv(load.TABLES_VARIABLE, str(path))

    def test_it_writes_the_document_to_standard_output(self, tables, capsys):
        assert cli.main(["profile", "--vendor", "Example Co"]) == 0
        output = capsys.readouterr().out
        assert output.startswith("<?xml")
        assert "<value>Example Co</value>" in output

    def test_or_to_a_file_with_the_listener_it_was_told(self, tables, tmp_path, capsys):
        out = tmp_path / "made" / "profile.xml"
        assert cli.main(["profile", "--out", str(out), "--bind", "0.0.0.0:20001"]) == 0
        root = ElementTree.parse(out).getroot()
        port = (
            "d:referenceDevice/d:configuration/d:networkConfig/d:tcpListenPort/"
            "d:currentValue/d:value"
        )
        assert _text(root, port) == "20001"
        assert capsys.readouterr().out == "", "nothing but the document goes to standard output"

    def test_validating_against_a_schema_that_is_not_there_says_so(self, tables, tmp_path, capsys):
        pytest.importorskip("xmlschema")
        assert cli.main(["profile", "--validate", str(tmp_path / "absent.xsd")]) == 2
        assert "no such schema" in capsys.readouterr().err

    @pytest.mark.skipif(not SCHEMA.is_file(), reason="the Users Group schema is obtained locally")
    def test_validating_against_the_real_schema_passes(self, tables, capsys):
        pytest.importorskip("xmlschema")
        assert cli.main(["profile", "--validate", str(SCHEMA)]) == 0
        assert "valid against" in capsys.readouterr().err


class TestAReadByIndexIsDeclaredAndAnswered:
    """The table says a static group may be read by index; the session agrees."""

    def test_every_static_row_lists_the_index_qualifiers(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        static = [
            row
            for row in table.rows
            if row.group in (1, 10, 20, 21, 30, 40) and row.request and row.request[0] == 1
        ]
        assert static
        for row in static:
            assert {0x17, 0x28} <= set(row.request[1]), row
            if row.response is not None:
                assert {0x17, 0x28} <= set(row.response[1]), row

    def test_the_answer_to_an_indexed_read_uses_a_qualifier_the_row_lists(self, simulation):
        session = simulation.outstation.session()
        table = device_profile.implementation(simulation.outstation, session.facts)
        sender = Sender(session)
        row = next(r for r in table.rows if r.group == 30 and r.variation == 1)
        for qualifier in (0x17, 0x28):
            response = sender.send(1, _read_header(simulation.outstation, row, qualifier))
            assert not _refused(response)
            assert response[6] == qualifier and qualifier in row.response[1]
