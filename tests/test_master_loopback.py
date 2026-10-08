"""The master against this library's own outstation, in one process.

The two halves of the library talking to each other. What these tests show is
that they agree and that the master's bookkeeping is right: what it stores is
what the outstation holds, what it confirms is retired, what it leaves
unconfirmed is still there. They do not show that either end reads the
standard correctly, since both stand on the same layers; the interoperability
jobs and the tests written from octets are what speak to that.
"""

from __future__ import annotations

import pytest
from profile_fixtures import for_reference_der

from py1815.application import FunctionCode, IIN2Bit, IINBit, class_header
from py1815.master import ALL, Loopback, MasterAssociation, Outcome, PointType
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.profile.outstation import DerOutstation


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def simulation() -> der.Simulation:
    return der.build(load.resolve(for_reference_der(), Composition()))


def _served(simulation: der.Simulation, kind: Kind) -> int:
    return len(simulation.outstation.served(kind))


class TestAnIntegrityPoll:
    def test_it_fills_the_store_with_what_the_outstation_holds(self, simulation):
        simulation.advance(1.0)
        master = Loopback(simulation.outstation.session())

        poll = master.integrity_poll()

        assert poll.complete and not poll.undecoded
        store = master.store
        assert len(store.points(PointType.BINARY_INPUT)) == _served(simulation, Kind.BI)
        assert len(store.points(PointType.ANALOG_INPUT)) == _served(simulation, Kind.AI)
        assert len(store.points(PointType.COUNTER)) == _served(simulation, Kind.CTR)
        assert len(store.points(PointType.FROZEN_COUNTER)) == 4
        watts = store.analog_input(der.AI_METER_FIRST + 4)
        assert watts.value == round(simulation.der.watts)
        assert watts.flags == 0x01 and not watts.from_event

    def test_it_reports_the_indications_it_was_sent(self, simulation):
        poll = Loopback(simulation.outstation.session()).integrity_poll()
        assert poll.iin.is_set(IINBit.DEVICE_RESTART)
        assert poll.iin.is_set(IINBit.NEED_TIME)

    def test_outputs_are_not_in_it_and_are_read_by_naming_them(self, simulation):
        """As the profile has it: output status is read by its group."""
        master = Loopback(simulation.outstation.session())
        master.integrity_poll()
        assert master.store.points(PointType.ANALOG_OUTPUT) == {}

        master.read(analog_outputs=ALL, binary_outputs=ALL)
        assert len(master.store.points(PointType.ANALOG_OUTPUT)) == _served(simulation, Kind.AO)
        assert len(master.store.points(PointType.BINARY_OUTPUT)) == _served(simulation, Kind.BO)

    def test_the_outputs_scan_reads_both_kinds_of_output_status(self, simulation):
        master = Loopback(simulation.outstation.session())

        scan = master.scan("outputs")

        assert scan.complete
        assert scan.request == bytes.fromhex("C0 01 0A 00 06 28 00 06")
        assert len(master.store.points(PointType.BINARY_OUTPUT)) == _served(simulation, Kind.BO)
        assert len(master.store.points(PointType.ANALOG_OUTPUT)) == _served(simulation, Kind.AO)
        assert master.store.points(PointType.ANALOG_INPUT) == {}

    def test_a_response_of_many_fragments_is_confirmed_through_to_the_end(self):
        point_map = load.resolve(for_reference_der(), Composition())
        device = der.ReferenceDer()
        outstation = DerOutstation(point_map, device.bind(point_map), block_octets=200)
        der.Simulation(device, outstation)
        master = Loopback(outstation.session(max_response=292))

        poll = master.integrity_poll()

        assert poll.complete and len(poll.fragments) > 1
        assert len(master.store.points(PointType.ANALOG_INPUT)) == len(outstation.served(Kind.AI))
        assert len(master.store.points(PointType.BINARY_INPUT)) == len(outstation.served(Kind.BI))


class TestEvents:
    def test_a_confirmed_event_scan_leaves_none_behind(self, simulation):
        master = Loopback(simulation.outstation.session())
        master.scan("events")
        simulation.advance(5.0)
        assert simulation.outstation.events.total > 0

        scan = master.scan("events")

        assert scan.complete
        events = [decoded for decoded in scan.objects if decoded.point is not None]
        assert events and all(event.event for event in events)
        assert simulation.outstation.events.total == 0, "confirmed, so retired"
        assert master.scan("events").objects == ()

    def test_a_binary_event_takes_its_time_from_the_common_time_sent_before_it(self, simulation):
        """Nobody has written the time, so the outstation stamps relative to a
        clock it says has not been set."""
        master = Loopback(simulation.outstation.session())
        simulation.advance(5.0)

        scan = master.scan("events")

        common = next(decoded for decoded in scan.objects if decoded.group == 51)
        binary = next(e for e in scan.objects if e.point is PointType.BINARY_INPUT)
        assert common.synchronized is False
        assert binary.time_ms is not None and binary.time_ms >= common.time_ms
        assert binary.synchronized is False

    def test_an_event_updates_the_point_it_is_about(self, simulation):
        master = Loopback(simulation.outstation.session())
        master.integrity_poll()
        simulation.advance(5.0)

        scan = master.scan("events")

        changed = next(event for event in scan.objects if event.point is PointType.ANALOG_INPUT)
        stored = master.store.analog_input(changed.index)
        assert stored.value == changed.value and stored.from_event
        assert changed in master.store.events

    def test_events_nobody_confirmed_are_sent_again(self, simulation):
        """By hand: with confirmation off, the outstation keeps what it sent."""
        master = Loopback(
            simulation.outstation.session(), association=MasterAssociation(confirm=False)
        )
        first = master.scan("events")
        second = master.scan("events")
        assert first.objects and len(second.objects) == len(first.objects)
        assert simulation.outstation.events.total == len(first.objects)

    def test_one_class_is_read_alone(self, simulation):
        master = Loopback(simulation.outstation.session())
        master.scan("events")
        simulation.advance(5.0)
        before = simulation.outstation.events.total

        scan = master.scan("class2")

        assert scan.complete
        assert simulation.outstation.events.total == before - len(scan.objects)


class TestReadingNamedPoints:
    def test_points_named_by_index_come_back_and_only_those(self, simulation):
        simulation.advance(1.0)
        master = Loopback(simulation.outstation.session())
        power = der.AI_METER_FIRST + 4

        answer = master.read(analog_inputs=[power], binary_inputs=[0, 1])

        assert answer.complete
        assert [(o.point, o.index) for o in answer.objects] == [
            (PointType.BINARY_INPUT, 0),
            (PointType.BINARY_INPUT, 1),
            (PointType.ANALOG_INPUT, power),
        ]
        assert master.store.analog_input(power).value == round(simulation.der.watts)
        assert len(master.store) == 3

    def test_a_point_the_outstation_does_not_have_is_a_result_and_not_an_exception(
        self, simulation
    ):
        answer = Loopback(simulation.outstation.session()).read(analog_inputs=[60000])
        assert answer.complete and answer.objects == ()
        assert answer.iin.is_set(IIN2Bit.PARAM_ERROR)

    def test_a_read_that_names_nothing_is_misuse(self, simulation):
        master = Loopback(simulation.outstation.session())
        with pytest.raises(ValueError, match="at least one point"):
            master.read()
        with pytest.raises(ValueError, match="'all'"):
            master.read(analog_inputs="every")

    def test_a_scan_nobody_defined_is_misuse(self, simulation):
        with pytest.raises(ValueError, match="'class4' is not a scan"):
            Loopback(simulation.outstation.session()).scan("class4")


class TestSilence:
    def test_an_outstation_that_does_not_answer_is_a_timeout(self, simulation):
        """It serves master address 1, and this master speaks from 9."""
        master = Loopback(
            simulation.outstation.session(), association=MasterAssociation(master_address=9)
        )
        poll = master.integrity_poll()
        assert poll.outcome is Outcome.TIMEOUT
        assert poll.fragments == () and len(master.store) == 0

    def test_and_the_next_request_is_made_as_usual(self, simulation):
        session = simulation.outstation.session()
        stranger = Loopback(session, association=MasterAssociation(master_address=9))
        stranger.integrity_poll()
        assert Loopback(session).integrity_poll().complete


class TestAnyRequest:
    def test_a_request_this_interface_does_not_name_can_still_be_made(self, simulation):
        master = Loopback(simulation.outstation.session())
        answer = master.request(FunctionCode.DELAY_MEASURE)
        assert answer.complete
        (delay,) = answer.objects
        assert (delay.group, delay.variation, delay.index) == (52, 2, None)

    def test_a_function_the_outstation_refuses_is_a_result(self, simulation):
        answer = Loopback(simulation.outstation.session()).request(FunctionCode.WARM_RESTART)
        assert answer.complete
        assert answer.iin.is_set(IIN2Bit.FUNC_NOT_SUPPORTED)


class TestUnsolicitedResponses:
    def _reporting(self, simulation) -> tuple[Loopback, Clock]:
        clock = Clock()
        session = simulation.outstation.session(unsolicited=True, clock=clock)
        return Loopback(session, clock=clock), clock

    def test_the_restart_announcement_is_taken_and_confirmed(self, simulation):
        master, _ = self._reporting(simulation)

        (announcement,) = master.listen()

        assert announcement.null and announcement.iin.is_set(IINBit.DEVICE_RESTART)
        assert master.listen() == [], "confirmed, so it is not sent again"

    def test_left_unconfirmed_it_is_sent_again_and_delivered_once(self, simulation):
        clock = Clock()
        session = simulation.outstation.session(unsolicited=True, clock=clock)
        master = Loopback(
            session, association=MasterAssociation(confirm=False, clock=clock), clock=clock
        )
        assert len(master.listen()) == 1
        clock.now += session.facts.unsolicited_confirm_timeout
        assert master.listen() == [], "the same octets again are not a new response"

    def test_events_of_an_enabled_class_arrive_unasked_and_are_stored(self, simulation):
        master, _ = self._reporting(simulation)
        master.listen()
        master.scan("events")
        enabled = master.request(
            FunctionCode.ENABLE_UNSOLICITED, b"".join(class_header(n) for n in (1, 2, 3))
        )
        assert enabled.complete and not enabled.iin.second
        simulation.advance(5.0)

        (report,) = master.listen()

        events = [decoded for decoded in report.objects if decoded.point is not None]
        assert events and all(event.event for event in events)
        assert simulation.outstation.events.total == 0, "confirmed, so retired"
        changed = next(e for e in report.objects if e.point is PointType.ANALOG_INPUT)
        assert master.store.analog_input(changed.index).value == changed.value
