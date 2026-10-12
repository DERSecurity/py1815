"""The checks that have the master break a protocol rule, and what each requires.

Each check passes against the simulated DER, in process and over a socket.
Each is also shown to fail: an outstation that answers a frame or a segment
it has to discard, one that stops answering after a damaged frame, and one
that clears events it was not sent the right confirmation for.

The sources of what is required: a frame with a bad checksum draws no answer
(IEEE 1815-2012 9.2.4.3, and the invalid CRC procedure of section 6.6.2 of the
DNP Users Group's IED Certification Procedure); a segment that is not a first
segment is discarded while no fragment is being assembled, and a first segment
replaces a series under way (IEEE 1815-2012 8.2.4, Table 8-1); events are not
removed without the matching confirmation (IEEE 1815-2012 Table 6-1, and
sections 8.5.2.2.4, 8.5.3.2.4 and 8.5.4.2.4 of the certification procedure).
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any

import pytest
import pytest_asyncio
from profile_fixtures import paired_reference_der

from py1815 import crc, link, transport
from py1815.application import AppControl, FunctionCode, Response
from py1815.decode import DecodedObject, PointType
from py1815.master import Deviations, MasterAssociation, Outstation
from py1815.master import bench as benches
from py1815.master.association import Exchange, Outcome
from py1815.master.bench import Bench, Check, Failed, NotApplicable, Result, Verdict
from py1815.master.checks import CATALOG, DEVIATION, DEVIATION_CHECKS, events_kept, select
from py1815.master.evaluate import Report, evaluate, evaluate_loopback
from py1815.master.loopback import Loopback
from py1815.master.profile import DerProfile, Plan
from py1815.master.tasks import Tasks
from py1815.profile import der, load
from py1815.profile.model import Composition, PointMap
from py1815.server import OutstationServer

PASSED, FAILED = Verdict.PASSED, Verdict.FAILED
NOT_RUN, NOT_APPLICABLE = Verdict.NOT_RUN, Verdict.NOT_APPLICABLE

SILENCE = ["LINK-001", "LINK-002", "LINK-003", "LINK-004", "TRANSPORT-001", "TRANSPORT-002"]
EVENTS = ["CONFIRM-001", "CONFIRM-002", "CONFIRM-003"]


def _points() -> PointMap:
    return load.resolve(paired_reference_der(), Composition())


def _run(session: Any, points: PointMap, *names: str, **options: Any) -> Report:
    """Run named checks against a session in this process, allowed to deviate."""
    options.setdefault("deviating", True)
    return evaluate_loopback(Loopback(session), points, checks=select(names), **options)


def _one(session: Any, points: PointMap, name: str, **options: Any) -> Result:
    return _run(session, points, name, **options).results[0]


def _session(points: PointMap) -> Any:
    return der.build(points).outstation.session(need_time=False)


# --------------------------------------------------- outstations that misbehave


class _Wrapped:
    """A session whose ``receive`` a subclass changes. Everything else is the session's."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)


def _whole(octets: bytes) -> list[link.LinkFrame] | None:
    """Return the frames of octets that are whole valid frames, or None when they are not."""
    frames = link.FrameReader().feed(octets)
    if sum(link.frame_size(len(frame.payload)) for frame in frames) != len(octets):
        return None
    return frames


class _Lenient(_Wrapped):
    """An outstation that reads what it has to discard.

    A frame whose checksum or length is wrong is read as the frame it was
    made from, and every segment is taken as a whole fragment whatever its
    FIR and FIN bits say.
    """

    def receive(self, octets: bytes) -> bytes:
        frames = _whole(octets)
        if frames is None:
            # One damaged frame with one block of user data: take the user
            # data that is there and check nothing.
            claimed = octets[2] - link.MIN_LENGTH
            carried = len(octets) - link.HEADER_SIZE
            size = claimed if claimed <= carried else carried - crc.SIZE
            destination, source = struct.unpack("<HH", octets[4:8])
            payload = octets[link.HEADER_SIZE : link.HEADER_SIZE + size]
            frames = [link.LinkFrame(octets[3], destination, source, payload)]
        repaired = b""
        for frame in frames:
            payload = frame.payload
            if payload:
                first_and_final = transport.FIR_MASK | transport.FIN_MASK
                payload = bytes([payload[0] | first_and_final]) + payload[1:]
            repaired += link.build(frame.control, frame.destination, frame.source, payload)
        return bytes(self._session.receive(repaired))


class _Deaf(_Wrapped):
    """An outstation that answers nothing more once it has been sent a damaged frame."""

    def __init__(self, session: Any) -> None:
        super().__init__(session)
        self._deaf = False

    def receive(self, octets: bytes) -> bytes:
        self._deaf = self._deaf or _whole(octets) is None
        return b"" if self._deaf else bytes(self._session.receive(octets))


class _SelfConfirming(_Wrapped):
    """An outstation that clears its events as soon as it has sent them.

    Each response that asks for a confirmation is confirmed here, on the
    master's behalf, whatever the master then sends.
    """

    def receive(self, octets: bytes) -> bytes:
        out = bytes(self._session.receive(octets))
        for frame in link.FrameReader().feed(out):
            payload = frame.payload
            first = len(payload) >= 2 and payload[0] & transport.FIR_MASK
            if first and payload[1] & 0x20:
                # The same sequence number and UNS bit, with FIR and FIN set
                # and function code 0, CONFIRM.
                control = 0xC0 | (payload[1] & 0x1F)
                fragment = bytes([transport.FIR_MASK | transport.FIN_MASK, control, 0x00])
                self._session.receive(link.build(0xC4, frame.source, frame.destination, fragment))
        return out


class _Unclearing(_Wrapped):
    """An outstation that never clears an event: it does not read confirmations."""

    def receive(self, octets: bytes) -> bytes:
        kept = b""
        for frame in link.FrameReader().feed(octets):
            payload = frame.payload
            # Function code 0, CONFIRM, after the transport and application control octets.
            if len(payload) >= 3 and payload[2] == 0x00:
                continue
            kept += link.build(frame.control, frame.destination, frame.source, payload)
        return bytes(self._session.receive(kept)) if kept else b""


# ------------------------------------------------------------------- the set


class TestTheSet:
    def test_the_set_is_named_and_selected_whole(self):
        assert select([DEVIATION]) == DEVIATION_CHECKS
        assert [check.id for check in DEVIATION_CHECKS] == [*SILENCE, *EVENTS]
        assert all(check.deviates and not check.commands for check in DEVIATION_CHECKS)
        assert {check.id for check in CATALOG if check.deviates} == {*SILENCE, *EVENTS}

    def test_a_run_not_allowed_to_deviate_runs_none_of_them_and_sends_nothing(self):
        points = _points()
        report = _run(_session(points), points, DEVIATION, deviating=False)
        assert not report.deviating
        for result in report.results:
            assert result.verdict is NOT_RUN and result.requests == 0
            assert result.detail == (
                "it breaks a protocol rule on purpose, and the run was not allowed to"
            )

    def test_a_run_allowed_to_deviate_says_so_in_its_report(self):
        points = _points()
        report = _run(_session(points), points, "LINK-001")
        assert report.deviating and report.describe()["allow_deviations"] is True
        assert report.lines()[0].endswith(", read only, allowed to deviate")
        assert (
            _run(_session(points), points, "MON-001", deviating=False).describe()[
                "allow_deviations"
            ]
            is False
        )


class TestAgainstTheSimulatedDer:
    @pytest.mark.parametrize("name", [*SILENCE, *EVENTS])
    def test_the_simulated_der_passes(self, name):
        points = _points()
        result = _one(_session(points), points, name)
        assert (result.verdict, result.detail) == (PASSED, ""), result
        assert result.requests > 0

    @pytest.mark.parametrize("name", ["LINK-003", "LINK-004"])
    def test_a_frame_that_is_too_short_takes_the_next_read_with_it(self, name):
        # The outstation waits for the octets the frame promised, and the
        # next frame supplies them. The read after that is answered.
        points = _points()
        (note,) = _one(_session(points), points, name).notes
        assert note.startswith("read 2 after ") and note.endswith("was the first to be answered")

    def test_events_already_confirmed_leave_nothing_to_check(self):
        points = _points()
        first, second = _run(_session(points), points, "CONFIRM-001", "CONFIRM-002").results
        assert first.verdict is PASSED
        assert (second.verdict, second.detail) == (
            NOT_APPLICABLE,
            "the outstation had no events to report",
        )

    def test_a_master_that_sends_no_confirmations_cannot_run_the_event_checks(self):
        points = _points()
        session = _session(points)
        facts = session.facts
        association = MasterAssociation(
            outstation_address=facts.outstation_address, master_address=1, confirm=False
        )
        report = evaluate_loopback(
            Loopback(session, association=association),
            points,
            checks=select(["CONFIRM-001"]),
            deviating=True,
        )
        (result,) = report.results
        assert (result.verdict, result.detail) == (
            NOT_APPLICABLE,
            "the master is set to send no confirmations",
        )


class TestAMasterWithDeviationsLeftOn:
    def test_a_check_begins_with_them_off_and_ends_with_them_on_again(self):
        # A header checksum left corrupt would damage the well-formed read the
        # check makes first, and the check would fail for it.
        points = _points()
        loopback = Loopback(_session(points))
        loopback.deviations.corrupt_header_crc = True
        report = evaluate_loopback(loopback, points, checks=select(["LINK-002"]), deviating=True)
        (result,) = report.results
        assert (result.verdict, result.detail) == (PASSED, "")
        assert loopback.deviations.on() == ("corrupt_header_crc",)

    def test_a_check_made_with_no_mark_keeps_what_was_on_and_adds_its_own(self):
        seen: list[tuple[str, ...]] = []

        def procedure(bench: Bench) -> Plan[None]:
            yield from bench.deviate("truncate")
            yield lambda target: seen.append(target.deviations.on())
            yield from bench.conform()
            yield lambda target: seen.append(target.deviations.on())

        points = _points()
        loopback = Loopback(_session(points))
        loopback.deviations.repeat_request = True
        check = Check("X-001", "A check made for this test", False, procedure)
        evaluate_loopback(loopback, points, checks=[check])
        assert seen == [("repeat_request", "truncate"), ("repeat_request",)]
        assert loopback.deviations.on() == ("repeat_request",)


def _event(index: int, value: int, time_ms: int | None) -> DecodedObject:
    """An analog input event, as the decoder reports one."""
    return DecodedObject(
        group=32,
        variation=3,
        index=index,
        value=value,
        flags=0x01,
        time_ms=time_ms,
        synchronized=None,
        point=PointType.ANALOG_INPUT,
        event=True,
        raw=b"",
    )


class _Scripted:
    """A master whose event reads return what a test wrote out, in order.

    It stands in for the master and the outstation together, so that a test
    can say exactly which events each read reports.
    """

    def __init__(self, *reads: list[DecodedObject]) -> None:
        self.deviations = Deviations()
        self.association = MasterAssociation()
        self._reads = list(reads)

    def scan(self, kind: str) -> Exchange:
        assert kind == "events"
        objects = tuple(self._reads.pop(0))
        response = Response(AppControl(con=bool(objects)), FunctionCode.RESPONSE, None)
        return Exchange(
            FunctionCode.READ, 0, b"", Outcome.COMPLETE, fragments=(response,), objects=objects
        )


class TestEventsThatAreEqual:
    A = _event(4, 100, 1_700_000_000_000)
    B = _event(5, 7, 1_700_000_000_500)

    def _carry_out(self, *reads: list[DecodedObject]) -> None:
        bench = Bench(DerProfile(_points()))
        plan = events_kept("withhold_confirmation", "no confirmation was sent")(bench)
        benches.drive(_Scripted(*reads), plan, lambda seconds: None)

    def test_an_event_reported_twice_has_to_be_reported_twice_again(self):
        # Two events equal in every field, and one of them missing from the
        # second read: an event was cleared without a confirmation.
        with pytest.raises(Failed, match="1 of 3 events were not reported again"):
            self._carry_out([self.A, self.B, self.A], [self.A, self.B])

    def test_the_same_events_in_another_order_are_the_same_events(self):
        both = [self.A, self.B, self.A]
        self._carry_out(both, [self.A, self.A, self.B], both, [])

    def test_no_events_is_not_applicable(self):
        with pytest.raises(NotApplicable, match="no events to report"):
            self._carry_out([])


class TestTheMasterAfterwards:
    def _check(self, procedure: Any) -> Check:
        return Check("X-001", "A check made for this test", False, procedure, deviates=True)

    def test_a_check_that_fails_while_deviating_leaves_the_master_as_it_was(self):
        def procedure(bench: Bench) -> Plan[None]:
            yield from bench.deviate("silence", "truncate")
            raise Failed("on purpose")

        points = _points()
        loopback = Loopback(_session(points))
        loopback.deviations.repeat_request = True
        report = evaluate_loopback(
            loopback, points, checks=[self._check(procedure)], deviating=True
        )
        assert report.results[0].verdict is FAILED
        assert loopback.deviations.on() == ("repeat_request",)

    def test_what_a_check_puts_back_is_sent_with_no_deviation_on(self):
        sent: list[tuple[str, ...]] = []

        def procedure(bench: Bench) -> Plan[None]:
            def put_back() -> Plan[None]:
                yield lambda target: sent.append(target.deviations.on())

            bench.afterwards("the test's own state", put_back)
            yield from bench.deviate("corrupt_header_crc")

        points = _points()
        loopback = Loopback(_session(points))
        evaluate_loopback(loopback, points, checks=[self._check(procedure)], deviating=True)
        assert sent == [()]
        assert not loopback.deviations.any_on()

    def test_every_check_of_the_set_leaves_the_master_conformant(self):
        points = _points()
        loopback = Loopback(_session(points))
        evaluate_loopback(loopback, points, checks=select([DEVIATION]), deviating=True)
        assert not loopback.deviations.any_on()
        assert loopback.integrity_poll().complete


# ----------------------------------------------------- shown to be able to fail


class TestAnOutstationThatMisbehaves:
    @pytest.mark.parametrize(
        ("name", "says"),
        [
            ("LINK-001", "the outstation answered a frame with a bad header checksum"),
            ("LINK-002", "the outstation answered a frame with a bad data checksum"),
            ("LINK-003", "the outstation answered a frame one octet short"),
            ("LINK-004", "the outstation answered a frame whose length claims more than it"),
            ("TRANSPORT-001", "the outstation answered a segment with no first segment"),
            ("TRANSPORT-002", "the outstation answered a request whose final segment never"),
        ],
    )
    def test_one_that_answers_what_it_has_to_discard_fails(self, name, says):
        points = _points()
        result = _one(_Lenient(_session(points)), points, name)
        assert result.verdict is FAILED and result.detail.startswith(says), result

    @pytest.mark.parametrize("name", ["LINK-001", "LINK-003"])
    def test_one_that_stops_answering_after_a_damaged_frame_fails(self, name):
        points = _points()
        result = _one(_Deaf(_session(points)), points, name)
        assert result.verdict is FAILED
        assert result.detail.startswith(
            "the outstation did not answer any of 3 well-formed reads sent after a frame"
        )

    @pytest.mark.parametrize(
        ("name", "though"),
        [
            ("CONFIRM-001", "no confirmation was sent"),
            ("CONFIRM-002", "the wrong sequence number was confirmed"),
            ("CONFIRM-003", "the confirmation was sent after the next request"),
        ],
    )
    def test_one_that_clears_events_it_was_not_confirmed_fails(self, name, though):
        points = _points()
        result = _one(_SelfConfirming(_session(points)), points, name)
        assert result.verdict is FAILED
        assert "events were not reported again though " + though in result.detail, result

    @pytest.mark.parametrize("name", EVENTS)
    def test_one_that_reports_events_again_after_they_were_confirmed_fails(self, name):
        points = _points()
        result = _one(_Unclearing(_session(points)), points, name)
        assert result.verdict is FAILED
        assert "events were reported again after they were confirmed" in result.detail, result

    def test_one_that_answers_no_read_at_all_fails_before_anything_is_bent(self):
        class _Hushed(_Wrapped):
            """An outstation that answers until it is told to stop."""

            hushed = False

            def receive(self, octets: bytes) -> bytes:
                return b"" if self.hushed else bytes(self._session.receive(octets))

        def hush(_bench: Bench) -> Plan[None]:
            yield lambda target: setattr(target.session, "hushed", True)

        # The reads that find out what is served are answered. The check's own
        # first read, sent with no deviation on, is not.
        points = _points()
        loopback = Loopback(_Hushed(_session(points)))
        stop = Check("X-000", "Stop the outstation answering", False, hush)
        report = evaluate_loopback(
            loopback, points, checks=[stop, *select(["LINK-001"])], deviating=True
        )
        result = report.results[1]
        assert result.verdict is FAILED
        assert result.detail == (
            "the outstation did not answer a well-formed read sent after the check began"
        )
        assert result.requests == 1, "nothing was sent with a deviation on"


# ------------------------------------------------------------ over a socket


@pytest_asyncio.fixture
async def served():
    """A simulated DER on a socket, and a connected master with a short timeout."""
    points = _points()
    simulation = der.build(points)
    server = OutstationServer(simulation.outstation.session(need_time=False), bind="127.0.0.1:0")
    await server.start()
    outstation = Outstation(
        "lab",
        host="127.0.0.1",
        port=server.port,
        tasks=Tasks.none(),
        reconnect=None,
        response_timeout=0.3,
    )
    await outstation.connect()
    try:
        yield points, outstation
    finally:
        await outstation.close()
        await server.stop()


@pytest.mark.asyncio
class TestOverASocket:
    async def test_the_set_passes_and_the_trace_holds_what_was_sent(self, served):
        points, outstation = served
        results: list[Result] = []
        report = await evaluate(
            outstation,
            points,
            checks=select([*SILENCE, "CONFIRM-001"]),
            deviating=True,
            on_result=results.append,
        )
        assert [(each.id, each.verdict, each.detail) for each in report.results] == [
            (name, PASSED, "") for name in [*SILENCE, "CONFIRM-001"]
        ]
        assert results == list(report.results), "each result was handed over as its check ended"
        assert not outstation.deviations.any_on()

        # The damaged frames are in the trace as they were sent, inside the
        # span of frames their check reports.
        first, last = report.results[0].frames
        damaged = [
            entry
            for entry in outstation.trace.since(first - 1)
            if entry.id <= last and "problem" in entry.link
        ]
        assert [entry.link["problem"] for entry in damaged] == ["header CRC does not match"]

    async def test_a_request_from_another_task_waits_while_the_outstation_is_held(self, served):
        _, outstation = served
        await outstation._reserve()
        waiting = asyncio.create_task(outstation.scan("class0"))
        await asyncio.sleep(0.2)
        assert not waiting.done(), "another task's request was sent while the outstation was held"
        assert (await outstation.scan("class0")).complete, "the holder's own request goes ahead"
        outstation._release()
        assert (await asyncio.wait_for(waiting, 5)).complete
        outstation._release()  # Letting go of an outstation that is not held does nothing.
        assert (await outstation.scan("class0")).complete

    async def test_a_check_that_deviates_holds_the_outstation_until_it_ends(self, served):
        points, outstation = served
        elsewhere: list[asyncio.Task[Any]] = []

        def procedure(bench: Bench) -> Plan[None]:
            yield from bench.deviate("silence")
            # A request from another task, as an automatic task or another
            # caller would make one while the check is under way.
            yield lambda target: elsewhere.append(asyncio.create_task(target.scan("class0")))
            yield from bench.pause(0.3)
            yield lambda target: elsewhere.append(elsewhere[0].done())

        check = Check("X-001", "A check made for this test", False, procedure, deviates=True)
        await evaluate(outstation, points, checks=[check], deviating=True)
        assert elsewhere[1] is False, "the request waited for the check to end"
        answered = await asyncio.wait_for(elsewhere[0], 5)
        assert answered.complete, "and was sent with no deviation on"

    async def test_a_run_that_is_cancelled_leaves_the_master_conformant_and_let_go(self, served):
        points, outstation = served

        def procedure(bench: Bench) -> Plan[None]:
            yield from bench.deviate("silence")
            yield from bench.pause(30)

        check = Check("X-001", "A check made for this test", False, procedure, deviates=True)
        outstation.deviations.repeat_request = True
        run = asyncio.create_task(evaluate(outstation, points, checks=[check], deviating=True))
        for _ in range(100):
            if outstation.deviations.silence:
                break
            await asyncio.sleep(0.05)
        assert outstation.deviations.silence, "the check is under way"

        run.cancel()
        with pytest.raises(asyncio.CancelledError):
            await run

        assert outstation.deviations.on() == ("repeat_request",)
        outstation.deviations.clear()
        assert (await asyncio.wait_for(outstation.scan("class0"), 5)).complete
