"""Unsolicited responses: what an outstation sends without being asked.

D69 to D71, and the plan in `docs/planning/UNSOLICITED.md`. The session does
no I/O, so "sends" means "returns from `initiate`", and every wait here is the
injected clock being moved. Requests go in through `_handle_fragment` as in
the other session tests; what `initiate` returns is framed, since it is what
an owner writes to a socket, and is unwrapped here by the framing helpers.

`test_session_unsolicited.py` holds the answers of a session built without
them, which is every session unless it says otherwise, and those tests are
unchanged. `TestOffIsOff` below adds what the new entry point does there:
nothing.
"""

from __future__ import annotations

import pytest

from py1815 import link
from py1815.application import FunctionCode, IIN2Bit, IINBit
from py1815.control import CommandStatus
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint, BinaryPoint
from py1815.session import (
    DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT,
    DEFAULT_UNSOLICITED_RESUME,
    Session,
)
from py1815.transport import Reassembler

OUTSTATION, MASTER = 1024, 1
TIMEOUT = DEFAULT_UNSOLICITED_CONFIRM_TIMEOUT

#: Group 60 variations 2, 3 and 4: classes 1, 2 and 3, all of each.
CLASS_1 = bytes([60, 2, 0x06])
CLASS_2 = bytes([60, 3, 0x06])
CLASS_3 = bytes([60, 4, 0x06])
CLASSES = CLASS_1 + CLASS_2 + CLASS_3
CLASS_0 = bytes([60, 1, 0x06])

#: What the provider answers a class 0 read with: one 32-bit analog input.
STATIC = bytes([30, 1, 0x00, 0, 0, 0x01, 0x2A, 0, 0, 0])

#: The restart indication, which stands until a master clears it.
RESTART = IINBit.DEVICE_RESTART

#: The write that clears it: group 80 variation 1, index 7, value 0.
CLEAR_RESTART = bytes([80, 1, 0x00, 7, 7, 0])

#: One analog event of group 32 variation 3 behind a one-octet index: flags,
#: a 32-bit value and a six-octet time.
EVENT_OCTETS = 1 + 1 + 4 + 6


class Reader:
    def read(self, headers):
        return STATIC


class Clock:
    """Seconds that pass only when a test says so."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Commands:
    """A control provider that records what reached it."""

    def __init__(self) -> None:
        self.operated: list = []

    def select(self, controls):
        return [CommandStatus.SUCCESS] * len(controls)

    def operate(self, controls):
        self.operated.append(list(controls))
        return [CommandStatus.SUCCESS] * len(controls)


def _built(**options) -> tuple[Session, EventBuffers, Clock]:
    clock = Clock()
    buffers = options.pop("events", None) or EventBuffers()
    options.setdefault("unsolicited", True)
    return Session(Reader(), events=buffers, clock=clock, **options), buffers, clock


def _request(function: int, body: bytes = b"", sequence: int = 0) -> bytes:
    return bytes([0xC0 | sequence, function]) + body


def _read(body: bytes, sequence: int = 0) -> bytes:
    return _request(FunctionCode.READ, body, sequence)


def _confirm(sequence: int, *, unsolicited: bool) -> bytes:
    return bytes([0xC0 | (0x10 if unsolicited else 0) | sequence, FunctionCode.CONFIRM])


def _fragments(octets: bytes) -> list[bytes]:
    """The application fragments in what the session returned for the wire."""
    found, reassembler = [], Reassembler()
    for frame in link.FrameReader().feed(octets):
        assert (frame.destination, frame.source) == (MASTER, OUTSTATION)
        whole = reassembler.add(frame.payload)
        if whole is not None:
            found.append(whole)
    return found


def _said(session: Session) -> list[bytes]:
    """What the outstation sends unasked, right now."""
    return _fragments(session.initiate())


def _one(session: Session) -> bytes:
    (fragment,) = _said(session)
    return fragment


def _announce(session: Session) -> None:
    """Get the initial null response sent and confirmed, as a master does first."""
    null = _one(session)
    assert session._handle_fragment(_confirm(null[0] & 0x0F, unsolicited=True)) == b""


def _enabled(*classes: bytes, **options) -> tuple[Session, EventBuffers, Clock]:
    """A session past its startup, with the named classes enabled (all three by default)."""
    session, buffers, clock = _built(**options)
    _announce(session)
    body = b"".join(classes) or CLASSES
    response = session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, body))
    assert response[3] == 0
    return session, buffers, clock


def _analog(buffers: EventBuffers, index: int, cls: EventClass = EventClass.CLASS_1) -> None:
    buffers.record_analog(index, AnalogPoint(float(index)), event_class=cls, timestamp_ms=1)


def _indices(fragment: bytes) -> list[int]:
    """The point indices of the analog events a response carries, in order."""
    body = fragment[4:]
    indices: list[int] = []
    while body:
        assert tuple(body[:3]) == (32, 3, 0x17), "one kind of event in these tests"
        count = body[3]
        for position in range(count):
            indices.append(body[4 + position * EVENT_OCTETS])
        body = body[4 + count * EVENT_OCTETS :]
    return indices


# --------------------------------------------------------------------- off


class TestOffIsOff:
    """A session built without unsolicited responses, which is the default."""

    def test_it_is_off_unless_asked_for(self):
        facts = Session(Reader()).facts

        assert facts.unsolicited is False

    def test_nothing_is_ever_initiated(self):
        clock, buffers = Clock(), EventBuffers()
        session = Session(Reader(), events=buffers, clock=clock)
        _analog(buffers, 0)

        for _ in range(10):
            assert session.initiate() == b""
            assert session.initiate_after() is None
            clock.now += 3600

    def test_asking_changes_nothing_about_the_session(self):
        """`initiate` on a session that sends nothing is not an event in its life."""
        buffers = EventBuffers()
        _analog(buffers, 0)
        asked, unasked = (Session(Reader(), events=buffers) for _ in range(2))
        asked.initiate()
        asked.initiate_after()

        for fragment in (
            _read(CLASS_1),
            _request(FunctionCode.ENABLE_UNSOLICITED, CLASSES, 1),
            _request(FunctionCode.DISABLE_UNSOLICITED, CLASSES, 2),
            _confirm(0, unsolicited=True),
        ):
            assert asked._handle_fragment(fragment) == unasked._handle_fragment(fragment)

    def test_enable_is_refused_and_enables_nothing(self):
        clock, buffers = Clock(), EventBuffers()
        session = Session(Reader(), events=buffers, clock=clock)

        response = session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))
        _analog(buffers, 0)

        assert response == bytes([0xC0, 0x81, RESTART, IIN2Bit.FUNC_NOT_SUPPORTED])
        assert session.unsolicited_classes == frozenset()
        assert session.initiate() == b""

    def test_a_read_is_never_held_back(self):
        """There is no unsolicited response for it to wait behind."""
        session = Session(Reader(), events=EventBuffers())

        assert session._handle_fragment(_read(CLASS_0))[4:] == STATIC

    def test_an_unsolicited_confirmation_still_retires_nothing(self):
        buffers = EventBuffers()
        _analog(buffers, 0)
        session = Session(Reader(), events=buffers)
        session._handle_fragment(_read(CLASS_1))

        assert session._handle_fragment(_confirm(0, unsolicited=True)) == b""
        assert buffers.total == 1


class TestWhatItRefusesToBeBuiltWith:
    def test_no_limit_on_a_solicited_confirmation(self):
        """Unsolicited reporting waits for a solicited response to be settled,
        and a wait with no end would silence it for good."""
        with pytest.raises(ValueError, match="confirm_timeout"):
            Session(Reader(), unsolicited=True, confirm_timeout=None)

    @pytest.mark.parametrize("timeout", [0, -1.0, float("nan")])
    def test_a_confirmation_timeout_that_is_no_wait(self, timeout):
        with pytest.raises(ValueError, match="unsolicited_confirm_timeout"):
            Session(Reader(), unsolicited=True, unsolicited_confirm_timeout=timeout)

    def test_a_negative_number_of_retries(self):
        with pytest.raises(ValueError, match="unsolicited_retries"):
            Session(Reader(), unsolicited=True, unsolicited_retries=-1)

    @pytest.mark.parametrize("resume", [0, -5.0])
    def test_a_resume_time_that_is_no_wait(self, resume):
        with pytest.raises(ValueError, match="unsolicited_resume"):
            Session(Reader(), unsolicited=True, unsolicited_resume=resume)

    def test_none_of_it_is_checked_when_the_feature_is_off(self):
        """Settings for something switched off are not a reason to refuse a
        session that worked before they existed."""
        Session(Reader(), confirm_timeout=None)

    def test_the_settings_are_reported_as_facts(self):
        facts = Session(
            Reader(),
            unsolicited=True,
            unsolicited_confirm_timeout=2.5,
            unsolicited_retries=4,
            unsolicited_resume=None,
        ).facts

        assert facts.unsolicited is True
        assert facts.unsolicited_confirm_timeout == 2.5
        assert facts.unsolicited_retries == 4
        assert facts.unsolicited_resume is None

    def test_the_defaults(self):
        facts = Session(Reader(), unsolicited=True).facts

        assert facts.unsolicited_confirm_timeout == 5.0
        assert facts.unsolicited_retries is None, "without limit"
        assert facts.unsolicited_resume == 60.0


# ---------------------------------------------------- enabling and disabling


class TestEnablingAndDisabling:
    def test_enabling_all_three_classes_is_answered_with_a_null_response(self):
        """The request and response the standard gives as its example, but for
        the sequence number and the restart indication this session still has."""
        session, _, _ = _built()

        response = session._handle_fragment(bytes.fromhex("c3143c02063c03063c0406"))

        assert response == bytes.fromhex("c3818000")
        assert session.unsolicited_classes == frozenset(EventClass)

    @pytest.mark.parametrize(
        ("body", "cls"),
        [
            (CLASS_1, EventClass.CLASS_1),
            (CLASS_2, EventClass.CLASS_2),
            (CLASS_3, EventClass.CLASS_3),
        ],
    )
    def test_a_class_is_enabled_on_its_own(self, body, cls):
        session, _, _ = _built()

        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, body))

        assert session.unsolicited_classes == frozenset({cls})

    def test_enabling_adds_to_what_is_enabled(self):
        session, _, _ = _built()
        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_1))

        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_3, 1))

        assert session.unsolicited_classes == {EventClass.CLASS_1, EventClass.CLASS_3}

    def test_disabling_removes_only_what_it_names(self):
        session, _, _ = _built()
        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))

        response = session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASS_2, 1))

        assert response == bytes([0xC1, 0x81, RESTART, 0])
        assert session.unsolicited_classes == {EventClass.CLASS_1, EventClass.CLASS_3}

    def test_nothing_is_enabled_until_a_master_enables_it(self):
        session, _, _ = _built()

        assert session.unsolicited_classes == frozenset()

    def test_disabling_what_was_never_enabled_is_not_an_error(self):
        """It is how a master puts an outstation in a known state at startup."""
        session, _, _ = _built()

        response = session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES))

        assert response[2:] == bytes([RESTART, 0])

    def test_a_class_with_no_events_can_be_enabled(self):
        session = Session(Reader(), unsolicited=True)

        response = session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))

        assert response[3] == 0, "accepted, with no event buffers at all"

    @pytest.mark.parametrize(
        "function", [FunctionCode.ENABLE_UNSOLICITED, FunctionCode.DISABLE_UNSOLICITED]
    )
    @pytest.mark.parametrize(
        ("body", "bit", "why"),
        [
            (CLASS_0, IIN2Bit.OBJECT_UNKNOWN, "class 0 is static data"),
            (CLASS_1 + CLASS_0, IIN2Bit.OBJECT_UNKNOWN, "class 0 beside a class that is fine"),
            (bytes([30, 0, 0x06]), IIN2Bit.OBJECT_UNKNOWN, "a point type, not a class"),
            (bytes([60, 2, 0x07, 5]), IIN2Bit.PARAM_ERROR, "a class with a count"),
            (bytes([60, 2, 0x00, 0, 3]), IIN2Bit.PARAM_ERROR, "a class with a range"),
            (b"", IIN2Bit.PARAM_ERROR, "nothing named"),
            (bytes([60, 2, 0x5B]), IIN2Bit.PARAM_ERROR, "a qualifier nobody accepts"),
        ],
    )
    def test_anything_else_is_refused_out_loud(self, function, body, bit, why):
        session, _, _ = _built()
        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_2))
        before = session.unsolicited_classes

        response = session._handle_fragment(_request(function, body, 1))

        assert response == bytes([0xC1, 0x81, RESTART, bit]), why
        assert session.unsolicited_classes == before, "and a refusal changes nothing"

    def test_a_restart_disables_every_class(self):
        session, _, _ = _built()
        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))

        session.restart()

        assert session.unsolicited_classes == frozenset()

    def test_a_new_connection_does_not(self):
        """What a master enabled belongs to the association, not to the socket."""
        session, _, _ = _built()
        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))

        session.connection_reset()

        assert session.unsolicited_classes == frozenset(EventClass)

    def test_the_function_can_still_be_disabled_by_configuration(self):
        session, _, _ = _built(disabled_functions=[FunctionCode.ENABLE_UNSOLICITED])

        response = session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))

        assert response[3] == IIN2Bit.FUNC_NOT_SUPPORTED
        assert session.unsolicited_classes == frozenset()


# ------------------------------------------------- the initial null response


class TestTheInitialNullResponse:
    def test_it_is_the_first_thing_said(self):
        """Function 130, first and final, asking to be confirmed, marked
        unsolicited, the restart indication set, and no objects."""
        session, _, _ = _built()

        assert _said(session) == [bytes.fromhex("f0828000")]

    def test_it_is_addressed_to_the_master(self):
        clock = Clock()
        session = Session(
            Reader(), unsolicited=True, clock=clock, outstation_address=10, master_address=77
        )

        (frame,) = link.FrameReader().feed(session.initiate())

        assert (frame.destination, frame.source) == (77, 10)
        assert frame.is_primary

    def test_it_is_sent_once_until_its_time_is_up(self):
        session, _, clock = _built()
        _said(session)

        clock.now += TIMEOUT - 0.001

        assert _said(session) == []

    def test_it_is_sent_again_every_timeout_for_as_long_as_it_takes(self):
        """No count of retries applies to it, however small."""
        session, _, clock = _built(unsolicited_retries=0)
        first = _one(session)

        for _ in range(200):
            clock.now += TIMEOUT
            assert _said(session) == [first], "the same octets under the same sequence"

    def test_it_says_when_to_ask_again(self):
        session, _, clock = _built()
        assert session.initiate_after() == 0.0

        session.initiate()

        assert session.initiate_after() == TIMEOUT
        clock.now += 2
        assert session.initiate_after() == TIMEOUT - 2
        clock.now += 10
        assert session.initiate_after() == 0.0

    def test_no_events_are_sent_before_it_is_confirmed(self):
        session, buffers, clock = _built()
        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES))
        _analog(buffers, 0)

        for _ in range(5):
            assert all(len(fragment) == 4 for fragment in _said(session))
            clock.now += TIMEOUT

    def test_its_confirmation_ends_it(self):
        session, _, clock = _built()
        _said(session)

        assert session._handle_fragment(_confirm(0, unsolicited=True)) == b""

        clock.now += 10 * TIMEOUT
        assert _said(session) == []
        assert session.initiate_after() is None

    def test_a_confirmation_naming_another_sequence_does_not(self):
        session, _, clock = _built()
        first = _one(session)

        session._handle_fragment(_confirm(7, unsolicited=True))

        clock.now += TIMEOUT
        assert _said(session) == [first]

    def test_a_solicited_confirmation_does_not(self):
        """The two exchanges count separately: the same number without the
        unsolicited bit names a different response."""
        session, _, clock = _built()
        first = _one(session)

        session._handle_fragment(_confirm(0, unsolicited=False))

        clock.now += TIMEOUT
        assert _said(session) == [first]

    def test_once_the_restart_is_cleared_the_retry_says_so_under_a_new_sequence(self):
        """A retry that differs in any octet is a new response, and a master
        tells a new response from a repeat by its sequence number."""
        session, _, clock = _built()
        assert _one(session) == bytes.fromhex("f0828000")

        cleared = session._handle_fragment(_request(FunctionCode.WRITE, CLEAR_RESTART))
        clock.now += TIMEOUT

        assert cleared == bytes.fromhex("c0810000")
        assert _said(session) == [bytes.fromhex("f1820000")]

    def test_the_confirmation_then_has_to_name_the_new_sequence(self):
        session, _, clock = _built()
        _said(session)
        session._handle_fragment(_request(FunctionCode.WRITE, CLEAR_RESTART))
        clock.now += TIMEOUT
        _said(session)

        session._handle_fragment(_confirm(0, unsolicited=True))
        assert session.initiate_after() is not None, "the old number confirms nothing"

        session._handle_fragment(_confirm(1, unsolicited=True))
        assert session.initiate_after() is None

    def test_a_restart_announces_itself_again(self):
        session, _, _ = _built()
        _announce(session)
        assert _said(session) == []

        session.restart()

        (null,) = _said(session)
        assert null[1:] == bytes([0x82, RESTART, 0])
        assert null[0] & 0xF0 == 0xF0

    def test_a_new_connection_does_not_once_it_was_confirmed(self):
        session, _, _ = _built()
        _announce(session)

        session.connection_reset()

        assert _said(session) == []

    def test_a_new_connection_gets_it_at_once_when_it_was_not(self):
        """The response in flight died with its socket. The restart is still
        unannounced, and the master that just connected is told now and not
        when a timer for the old connection would have run out."""
        session, _, clock = _built()
        _said(session)
        clock.now += 1

        session.connection_reset()

        (null,) = _said(session)
        assert null[1:] == bytes([0x82, RESTART, 0])


# ------------------------------------------------------------- the events


class TestReportingEvents:
    def test_an_event_in_an_enabled_class_is_sent(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 3)

        fragment = _one(session)

        # F1: first, final, confirm, unsolicited, sequence 1. Then function
        # 130, the restart indication, and group 32 variation 3 with a one-octet
        # count and index: point 3, online, value 3, at time 1.
        assert fragment == bytes.fromhex("f182800020031701030103000000010000000000")

    def test_nothing_is_sent_when_nothing_has_happened(self):
        session, _, clock = _enabled()

        clock.now += 3600

        assert _said(session) == []
        assert session.initiate_after() is None

    def test_an_event_in_a_class_nobody_enabled_is_kept_and_not_sent(self):
        session, buffers, clock = _enabled(CLASS_1)
        _analog(buffers, 0, EventClass.CLASS_2)

        clock.now += 3600

        assert _said(session) == []
        assert buffers.count(EventClass.CLASS_2) == 1

    def test_only_the_enabled_classes_travel(self):
        session, buffers, _ = _enabled(CLASS_1, CLASS_3)
        _analog(buffers, 1, EventClass.CLASS_1)
        _analog(buffers, 2, EventClass.CLASS_2)
        _analog(buffers, 3, EventClass.CLASS_3)

        assert _indices(_one(session)) == [1, 3]

    def test_the_indications_ask_for_what_was_left_behind(self):
        session, buffers, _ = _enabled(CLASS_1)
        _analog(buffers, 1, EventClass.CLASS_1)
        _analog(buffers, 2, EventClass.CLASS_2)

        fragment = _one(session)

        assert fragment[2] & IINBit.CLASS_2_EVENTS
        assert not fragment[2] & IINBit.CLASS_1_EVENTS, "class 1 is all in this response"

    def test_events_recorded_before_the_class_was_enabled_are_sent_once_it_is(self):
        session, buffers, _ = _built()
        _announce(session)
        _analog(buffers, 5)
        assert _said(session) == []

        session._handle_fragment(_request(FunctionCode.ENABLE_UNSOLICITED, CLASS_1))

        assert _indices(_one(session)) == [5]

    def test_events_are_sent_in_the_order_they_happened_across_classes(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 1, EventClass.CLASS_3)
        _analog(buffers, 2, EventClass.CLASS_1)
        _analog(buffers, 3, EventClass.CLASS_2)

        assert _indices(_one(session)) == [1, 2, 3]

    def test_a_binary_event_travels_as_a_poll_would_send_it(self):
        """The same encoder, so the same variation: group 2 variation 2."""
        session, buffers, _ = _enabled()
        buffers.record_binary(
            4, BinaryPoint(True), event_class=EventClass.CLASS_1, timestamp_ms=0x0102
        )

        unsolicited = _one(session)
        session._handle_fragment(_confirm(1, unsolicited=True))
        buffers.record_binary(
            4, BinaryPoint(False), event_class=EventClass.CLASS_1, timestamp_ms=0x0102
        )
        session.connection_reset()
        polled = session._handle_fragment(_read(CLASS_1))

        assert unsolicited[4:8] == bytes([2, 2, 0x17, 1])
        assert polled[4:8] == unsolicited[4:8]

    def test_the_events_stay_buffered_until_the_confirmation(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)

        _said(session)

        assert buffers.total == 1

    def test_the_confirmation_retires_them(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)

        assert session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True)) == b""

        assert buffers.total == 0
        clock.now += 10 * TIMEOUT
        assert _said(session) == []

    def test_a_confirmation_naming_another_sequence_retires_nothing(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)

        session._handle_fragment(_confirm((fragment[0] + 1) & 0x0F, unsolicited=True))

        assert buffers.total == 1

    def test_a_solicited_confirmation_retires_nothing(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)

        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=False))

        assert buffers.total == 1

    def test_a_late_confirmation_of_the_response_last_sent_still_counts(self):
        """A master does not time an unsolicited response out; it confirms on
        receipt. One naming the response last sent means that response
        arrived, however long the confirmation took."""
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)

        clock.now += 10 * TIMEOUT
        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert buffers.total == 0

    def test_only_events_recorded_before_it_was_built_are_retired(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)
        _analog(buffers, 1)

        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert buffers.total == 1
        assert _indices(_one(session)) == [1]

    def test_unsolicited_sequence_numbers_are_a_series_of_their_own(self):
        """Requests at sequences 9 and 10 in between do not move it."""
        session, buffers, _ = _enabled()
        sequences = []
        for index in range(3):
            _analog(buffers, index)
            fragment = _one(session)
            sequences.append(fragment[0] & 0x0F)
            session._handle_fragment(_request(FunctionCode.DELAY_MEASURE, sequence=9 + index))
            session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert sequences == [1, 2, 3], "after the null response at 0"

    def test_the_sequence_wraps_at_sixteen(self):
        session, buffers, _ = _enabled()
        sequences = []
        for index in range(18):
            _analog(buffers, index)
            fragment = _one(session)
            sequences.append(fragment[0] & 0x0F)
            session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert sequences == [*range(1, 16), 0, 1, 2]

    def test_a_response_is_one_fragment_and_the_rest_follows_its_confirmation(self):
        """Fitted to what the master can receive by the same code a poll is,
        and never continued: every unsolicited response is first and final."""
        ceiling = 4 + 4 + 3 * EVENT_OCTETS
        session, buffers, _ = _enabled(max_response=ceiling)
        for index in range(7):
            _analog(buffers, index)

        seen = []
        for _ in range(3):
            fragment = _one(session)
            assert len(fragment) <= ceiling
            assert fragment[0] & 0xC0 == 0xC0, "first and final"
            assert fragment[2] & IINBit.CLASS_1_EVENTS or len(seen) == 2
            seen.append(_indices(fragment))
            assert _said(session) == [], "nothing more until this one is confirmed"
            session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert seen == [[0, 1, 2], [3, 4, 5], [6]]
        assert buffers.total == 0

    def test_an_overflow_is_reported_and_cleared_by_the_confirmation(self):
        session, buffers, _ = _enabled(events=EventBuffers(capacity=2))
        for index in range(3):
            _analog(buffers, index)

        fragment = _one(session)
        assert fragment[3] & IIN2Bit.EVENT_BUFFER_OVERFLOW
        assert buffers.overflowed()

        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))
        assert not buffers.overflowed()

    def test_an_overflow_since_it_was_sent_is_not_cleared_by_its_confirmation(self):
        session, buffers, _ = _enabled(events=EventBuffers(capacity=2))
        for index in range(3):
            _analog(buffers, index)
        fragment = _one(session)
        _analog(buffers, 9)

        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert buffers.overflowed(), "that loss the master has not been told about"

    def test_nothing_is_sent_when_no_event_fits_a_fragment(self):
        """A ceiling under which no event fits is allowed (D27). Nothing can
        be said unsolicited then, and an empty response is not sent in its
        place."""
        session, buffers, clock = _enabled(max_response=8)
        _analog(buffers, 0)

        for _ in range(3):
            assert _said(session) == []
            assert session.initiate_after() is None, "and it does not ask to be asked again"
            clock.now += TIMEOUT
        assert buffers.total == 1

    def test_disabling_a_class_stops_its_events_being_sent(self):
        session, buffers, _ = _enabled()

        session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASS_1, 1))
        _analog(buffers, 0)

        assert _said(session) == []
        assert buffers.total == 1, "and discards nothing"

    def test_disabling_while_one_is_unconfirmed_still_lets_it_be_confirmed(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)

        session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES, 1))
        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))

        assert buffers.total == 0

    def test_disabling_while_one_is_unconfirmed_ends_its_retries(self):
        """What is sent in place of an unconfirmed response is built from the
        classes still enabled, and there are none."""
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        _said(session)

        session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASSES, 1))
        clock.now += TIMEOUT

        assert _said(session) == []
        assert session.initiate_after() is None
        assert buffers.total == 1

    def test_a_retry_after_one_class_is_disabled_carries_only_the_others(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 1, EventClass.CLASS_1)
        _analog(buffers, 2, EventClass.CLASS_2)
        first = _one(session)

        session._handle_fragment(_request(FunctionCode.DISABLE_UNSOLICITED, CLASS_1, 1))
        clock.now += TIMEOUT
        second = _one(session)

        assert _indices(first) == [1, 2]
        assert _indices(second) == [2]
        assert second[0] & 0x0F == (first[0] + 1) & 0x0F, "a different response, so a new number"


# -------------------------------------------------------------- the retries


class TestRetries:
    def test_an_unconfirmed_response_is_sent_again_when_its_time_is_up(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)

        clock.now += TIMEOUT - 0.001
        assert _said(session) == []
        clock.now += 0.001

        assert _said(session) == [first], "octet for octet, sequence included"

    def test_the_timeout_is_the_one_configured(self):
        session, buffers, clock = _enabled(unsolicited_confirm_timeout=1.5)
        _analog(buffers, 0)
        _said(session)

        assert session.initiate_after() == 1.5
        clock.now += 1.5

        assert len(_said(session)) == 1

    def test_a_retry_carries_what_has_happened_since_under_a_new_sequence(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)
        _analog(buffers, 1)

        clock.now += TIMEOUT
        second = _one(session)

        assert _indices(second) == [0, 1]
        assert second[0] & 0x0F == (first[0] & 0x0F) + 1

    def test_the_confirmation_of_the_replaced_response_is_late(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)
        _analog(buffers, 1)
        clock.now += TIMEOUT
        second = _one(session)

        session._handle_fragment(_confirm(first[0] & 0x0F, unsolicited=True))
        assert buffers.total == 2

        session._handle_fragment(_confirm(second[0] & 0x0F, unsolicited=True))
        assert buffers.total == 0

    def test_a_retry_leaves_out_an_event_the_buffer_has_since_evicted(self):
        """Built from the buffer as it stands: an event already reported lost
        is not then reported."""
        session, buffers, clock = _enabled(events=EventBuffers(capacity=2))
        _analog(buffers, 0)
        _analog(buffers, 1)
        _said(session)
        _analog(buffers, 2)

        clock.now += TIMEOUT
        second = _one(session)

        assert _indices(second) == [1, 2]
        assert second[3] & IIN2Bit.EVENT_BUFFER_OVERFLOW

    def test_retries_are_without_limit_by_default(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)

        for _ in range(500):
            clock.now += TIMEOUT
            assert _said(session) == [first]

    @pytest.mark.parametrize("retries", [0, 1, 3])
    def test_a_limit_is_the_number_of_times_it_is_sent_again(self, retries):
        session, buffers, clock = _enabled(unsolicited_retries=retries, unsolicited_resume=None)
        _analog(buffers, 0)
        sent = len(_said(session))

        for _ in range(retries + 5):
            clock.now += TIMEOUT
            sent += len(_said(session))

        assert sent == 1 + retries

    def test_giving_up_loses_nothing(self):
        session, buffers, clock = _enabled(unsolicited_retries=1, unsolicited_resume=None)
        _analog(buffers, 7)
        _said(session)
        for _ in range(4):
            clock.now += TIMEOUT
            _said(session)

        polled = session._handle_fragment(_read(CLASS_1))

        assert buffers.total == 1
        assert _indices(polled) == [7], "and a class poll reads it"
        assert polled[0] & 0x20, "asking to be confirmed, as any event response does"

    def test_after_giving_up_it_starts_again_when_the_resume_time_comes(self):
        session, buffers, clock = _enabled(unsolicited_retries=1, unsolicited_resume=30.0)
        _analog(buffers, 0)
        _said(session)
        clock.now += TIMEOUT
        _said(session)
        clock.now += TIMEOUT
        assert _said(session) == [], "the retry was spent"

        assert session.initiate_after() == 30.0
        clock.now += 29.9
        assert _said(session) == []
        clock.now += 1.0
        assert session.initiate_after() == 0.0, "due, and not overdue by a negative wait"

        assert _indices(_one(session)) == [0]

    def test_the_new_series_has_its_own_retries(self):
        session, buffers, clock = _enabled(unsolicited_retries=1, unsolicited_resume=30.0)
        _analog(buffers, 0)
        sent = len(_said(session))
        for _ in range(100):
            clock.now += TIMEOUT
            sent += len(_said(session))

        # Each series is two transmissions over ten seconds and then a rest
        # of thirty: about one series every forty.
        assert 20 <= sent <= 30

    def test_after_giving_up_a_new_event_starts_it_again(self):
        session, buffers, clock = _enabled(unsolicited_retries=0, unsolicited_resume=None)
        _analog(buffers, 0)
        _said(session)
        clock.now += TIMEOUT
        assert _said(session) == []
        assert session.initiate_after() is None

        _analog(buffers, 1)

        assert _indices(_one(session)) == [0, 1]

    def test_after_giving_up_a_request_from_the_master_starts_it_again(self):
        session, buffers, clock = _enabled(unsolicited_retries=0, unsolicited_resume=None)
        _analog(buffers, 0)
        _said(session)
        clock.now += TIMEOUT
        assert _said(session) == []

        session._handle_fragment(_request(FunctionCode.DELAY_MEASURE, sequence=4))

        assert _indices(_one(session)) == [0]

    def test_after_giving_up_a_broadcast_from_the_master_starts_it_again(self):
        """A broadcast is a request from the master too, though nobody answers it."""
        session, buffers, clock = _enabled(unsolicited_retries=0, unsolicited_resume=None)
        _analog(buffers, 0)
        _said(session)
        clock.now += TIMEOUT
        assert _said(session) == []

        assert session.receive(_broadcast(_request(FunctionCode.DELAY_MEASURE))) == b""

        assert _indices(_one(session)) == [0]

    def test_after_giving_up_a_new_connection_starts_it_again(self):
        session, buffers, clock = _enabled(unsolicited_retries=0, unsolicited_resume=None)
        _analog(buffers, 0)
        _said(session)
        clock.now += TIMEOUT
        assert _said(session) == []

        session.connection_reset()

        assert _indices(_one(session)) == [0]

    def test_with_no_resume_time_only_those_three_start_it_again(self):
        session, buffers, clock = _enabled(unsolicited_retries=0, unsolicited_resume=None)
        _analog(buffers, 0)
        _said(session)
        clock.now += TIMEOUT
        _said(session)

        clock.now += 30 * 86_400

        assert _said(session) == []
        assert buffers.total == 1

    def test_the_default_resume_time(self):
        assert DEFAULT_UNSOLICITED_RESUME == 60.0

    def test_a_new_connection_sends_what_was_in_flight_at_once(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        _said(session)
        clock.now += 1

        session.connection_reset()

        assert _indices(_one(session)) == [0]


# -------------------------------------------- beside the solicited exchange


class TestARequestWhileOneIsUnconfirmed:
    def test_a_read_is_not_answered_while_one_waits(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        _said(session)

        assert session._handle_fragment(_read(CLASSES)) == b""

    def test_the_confirmation_answers_it_and_the_events_are_not_reported_twice(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        unsolicited = _one(session)
        session._handle_fragment(_read(CLASSES + CLASS_0, sequence=6))

        answer = session._handle_fragment(_confirm(unsolicited[0] & 0x0F, unsolicited=True))

        assert answer[0] == 0xC6, "the read's own sequence, and nothing to confirm"
        assert answer[1] == FunctionCode.RESPONSE
        assert answer[4:] == STATIC, "the static data, and no event: it was retired first"
        assert buffers.total == 0

    def test_the_held_read_reports_what_the_unsolicited_response_did_not_carry(self):
        session, buffers, _ = _enabled(CLASS_1)
        _analog(buffers, 1, EventClass.CLASS_1)
        _analog(buffers, 2, EventClass.CLASS_2)
        unsolicited = _one(session)
        session._handle_fragment(_read(CLASSES))

        answer = session._handle_fragment(_confirm(unsolicited[0] & 0x0F, unsolicited=True))

        assert _indices(unsolicited) == [1]
        assert _indices(answer) == [2]

    def test_when_the_confirmation_never_comes_the_read_is_answered_at_the_timeout(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        unsolicited = _one(session)
        session._handle_fragment(_read(CLASSES, sequence=6))
        assert session.initiate_after() == TIMEOUT

        clock.now += TIMEOUT
        (answer,) = _said(session)

        assert answer[1] == FunctionCode.RESPONSE, "the read's answer, and not a retry"
        assert answer[0] == 0xE6, "solicited, at the read's sequence, asking to be confirmed"
        assert _indices(answer) == _indices(unsolicited) == [0]

    def test_and_those_events_are_then_the_solicited_exchanges_to_retire(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        unsolicited = _one(session)
        session._handle_fragment(_read(CLASSES, sequence=6))
        clock.now += TIMEOUT
        _said(session)

        session._handle_fragment(_confirm(unsolicited[0] & 0x0F, unsolicited=True))
        assert buffers.total == 1, "the unsolicited response was given up on"

        session._handle_fragment(_confirm(6, unsolicited=False))
        assert buffers.total == 0
        assert _said(session) == []

    def test_nothing_unsolicited_follows_until_that_answer_is_settled(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        _said(session)
        session._handle_fragment(_read(CLASSES, sequence=6))
        clock.now += TIMEOUT
        _said(session)
        _analog(buffers, 1)

        clock.now += 9.9
        assert _said(session) == []

        clock.now += 0.1
        assert _indices(_one(session)) == [0, 1], "the solicited confirmation timed out"

    def test_a_read_of_static_data_held_to_the_timeout_is_followed_by_a_new_response(self):
        """The read took none of the events, so they are still to be reported,
        and the master has just shown it is there."""
        session, buffers, clock = _enabled(unsolicited_retries=0, unsolicited_resume=None)
        _analog(buffers, 0)
        first = _one(session)
        session._handle_fragment(_read(CLASS_0, sequence=6))

        clock.now += TIMEOUT
        answer, again = _said(session)

        assert answer[1] == FunctionCode.RESPONSE and answer[4:] == STATIC
        assert again[1] == FunctionCode.UNSOLICITED_RESPONSE
        assert _indices(again) == [0]
        assert again[0] & 0x0F == (first[0] & 0x0F) + 1, "a new response, not a retry"

    def test_a_second_read_replaces_the_first(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        unsolicited = _one(session)
        session._handle_fragment(_read(CLASS_0, sequence=6))
        session._handle_fragment(_read(CLASSES, sequence=7))

        answer = session._handle_fragment(_confirm(unsolicited[0] & 0x0F, unsolicited=True))

        assert answer[0] & 0x0F == 7
        assert answer[4:] == b"", "the class read's answer, and not the static data"

    def test_another_request_is_answered_at_once(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        _said(session)

        response = session._handle_fragment(_request(FunctionCode.WRITE, CLEAR_RESTART, 3))

        assert response[:2] == bytes([0xC3, 0x81])
        assert not response[2] & RESTART
        assert response[3] == 0

    def test_and_the_unsolicited_response_goes_on_waiting(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)
        session._handle_fragment(_request(FunctionCode.DELAY_MEASURE, sequence=3))

        assert session.initiate_after() == TIMEOUT
        clock.now += TIMEOUT

        assert _said(session) == [first]

    def test_another_request_discards_a_held_read(self):
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)
        session._handle_fragment(_read(CLASSES, sequence=6))

        session._handle_fragment(_request(FunctionCode.DELAY_MEASURE, sequence=7))
        clock.now += TIMEOUT

        assert _said(session) == [first], "a retry, with no read left to answer in its place"
        assert session._handle_fragment(_confirm(first[0] & 0x0F, unsolicited=True)) == b""

    def test_a_request_that_takes_no_response_discards_it_too(self):
        commands = Commands()
        session, buffers, _ = _enabled(control_provider=commands)
        _analog(buffers, 0)
        first = _one(session)
        session._handle_fragment(_read(CLASSES, sequence=6))
        latch_on = bytes([12, 1, 0x17, 1, 0, 0x03, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE_NR, latch_on, 7))

        assert len(commands.operated) == 1
        assert session._handle_fragment(_confirm(first[0] & 0x0F, unsolicited=True)) == b""

    def test_a_held_read_dies_with_its_connection(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        _said(session)
        session._handle_fragment(_read(CLASS_0, sequence=6))

        session.connection_reset()
        said = _said(session)

        assert [fragment[1] for fragment in said] == [FunctionCode.UNSOLICITED_RESPONSE]

    def test_a_read_is_held_behind_the_null_response_too(self):
        session, _, _ = _built()
        null = _one(session)

        assert session._handle_fragment(_read(CLASS_0, sequence=2)) == b""
        answer = session._handle_fragment(_confirm(null[0] & 0x0F, unsolicited=True))

        assert answer == bytes([0xC2, 0x81, RESTART, 0]) + STATIC

    def test_behind_an_unconfirmed_null_response_it_is_answered_and_the_null_sent_again(self):
        session, _, clock = _built()
        null = _one(session)
        session._handle_fragment(_read(CLASS_0, sequence=2))

        clock.now += TIMEOUT
        answer, again = _said(session)

        assert answer == bytes([0xC2, 0x81, RESTART, 0]) + STATIC
        assert again[1:] == null[1:]

    def test_a_read_that_is_not_one_is_refused_at_once(self):
        """A fragment that does not parse is not a read to hold."""
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        _said(session)

        response = session._handle_fragment(_read(bytes([60, 2, 0x5B])))

        assert response[3] & IIN2Bit.PARAM_ERROR


class TestAnEventWhileASolicitedResponseIsUnconfirmed:
    def _polled(self, **options):
        session, buffers, clock = _enabled(**options)
        _analog(buffers, 0)
        polled = session._handle_fragment(_read(CLASSES, sequence=4))
        assert polled[0] == 0xE4 and _indices(polled) == [0]
        return session, buffers, clock

    def test_nothing_unsolicited_is_sent_while_it_waits(self):
        session, buffers, clock = self._polled()
        _analog(buffers, 1)

        assert _said(session) == []
        assert session.initiate_after() == 10.0
        clock.now += 9.9
        assert _said(session) == []

    def test_its_confirmation_retires_its_events_and_the_rest_are_then_sent(self):
        session, buffers, _ = self._polled()
        _analog(buffers, 1)

        session._handle_fragment(_confirm(4, unsolicited=False))

        assert _indices(_one(session)) == [1], "event 0 was confirmed and is not sent again"

    def test_when_it_is_confirmed_and_nothing_is_left_nothing_is_sent(self):
        session, _, clock = self._polled()

        session._handle_fragment(_confirm(4, unsolicited=False))
        clock.now += 3600

        assert _said(session) == []

    def test_when_its_time_runs_out_the_events_go_unsolicited(self):
        session, buffers, clock = self._polled()

        clock.now += 10.0
        fragment = _one(session)

        assert fragment[1] == FunctionCode.UNSOLICITED_RESPONSE
        assert _indices(fragment) == [0]
        assert buffers.total == 1

    def test_a_late_solicited_confirmation_then_retires_nothing(self):
        session, buffers, clock = self._polled()
        clock.now += 10.0
        fragment = _one(session)

        session._handle_fragment(_confirm(4, unsolicited=False))
        assert buffers.total == 1

        session._handle_fragment(_confirm(fragment[0] & 0x0F, unsolicited=True))
        assert buffers.total == 0, "retired once, by the exchange that still held them"

    def test_the_wait_is_the_solicited_confirmation_timeout(self):
        session, _, clock = self._polled(confirm_timeout=2.0)

        assert session.initiate_after() == 2.0
        clock.now += 2.0

        assert len(_said(session)) == 1

    def test_a_retry_waits_for_a_solicited_confirmation_as_well(self):
        """A request other than a read is answered while an unsolicited
        response waits, and its answer can ask to be confirmed: one that
        reports a broadcast does. The retry holds off until that is settled."""
        session, buffers, clock = _enabled()
        _analog(buffers, 0)
        first = _one(session)
        clock.now += TIMEOUT - 1
        session.receive_broadcast(_broadcast(_request(FunctionCode.DELAY_MEASURE)))
        answer = session._handle_fragment(_request(FunctionCode.DELAY_MEASURE, sequence=3))
        assert answer[0] & 0x20, "the answer reports the broadcast and asks to be confirmed"

        clock.now += 1
        assert _said(session) == [], "the retry is due, and held"
        session._handle_fragment(_confirm(3, unsolicited=False))

        (second,) = _said(session)
        assert _indices(second) == _indices(first)


def _broadcast(fragment: bytes) -> bytes:
    """One request addressed to every outstation, asking for its report to be confirmed."""
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return link.build(control, destination=0xFFFE, source=MASTER, payload=b"\xc0" + fragment)


# ------------------------------------------------------- where it is sent


class TestWithNobodyToSendTo:
    """The destination comes from one helper, so that a session which does not
    know its master until one speaks has one place to say so."""

    def test_nothing_is_sent_while_there_is_no_master(self, monkeypatch):
        session, buffers, clock = _built()
        monkeypatch.setattr(session, "_unsolicited_destination", lambda: None)
        _analog(buffers, 0)

        for _ in range(3):
            assert session.initiate() == b""
            assert session.initiate_after() is None
            clock.now += TIMEOUT

    def test_and_it_is_once_there_is(self, monkeypatch):
        session, _, _ = _built()
        known: list[int] = []
        monkeypatch.setattr(
            session, "_unsolicited_destination", lambda: known[0] if known else None
        )
        assert session.initiate() == b""

        known.append(MASTER)

        assert _said(session) == [bytes.fromhex("f0828000")]

    def test_the_helper_names_the_configured_master(self):
        session = Session(Reader(), unsolicited=True, master_address=42)

        assert session._unsolicited_destination() == 42

    def test_a_session_that_takes_any_master_has_none_configured_and_sends_none(self):
        """Not even once a master has spoken and enabled every class."""
        session, buffers, clock = _built(outstation_address=OUTSTATION, master_address=None)
        control = link.control_byte(
            from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        enable = _request(FunctionCode.ENABLE_UNSOLICITED, CLASSES)
        answered = session.receive(link.build(control, OUTSTATION, 7, b"\xc0" + enable))
        (frame,) = link.FrameReader().feed(answered)
        assert frame.destination == session.master_address == 7
        _analog(buffers, 0)

        for _ in range(3):
            assert session.initiate() == b""
            assert session.initiate_after() is None
            clock.now += TIMEOUT
        assert buffers.total == 1, "the event waits for a poll"


class TestThroughTheLinkLayer:
    """The same exchange, entering through `receive` as octets from a socket do."""

    @staticmethod
    def _frames(fragment: bytes) -> bytes:
        control = link.control_byte(
            from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        return link.build(control, OUTSTATION, MASTER, b"\xc0" + fragment)

    def test_enable_report_confirm(self):
        session, buffers, _ = _built()
        null = _one(session)
        assert session.receive(self._frames(_confirm(null[0] & 0x0F, unsolicited=True))) == b""
        enabled = _fragments(
            session.receive(self._frames(_request(FunctionCode.ENABLE_UNSOLICITED, CLASSES)))
        )
        assert enabled == [bytes([0xC0, 0x81, RESTART, 0])]

        _analog(buffers, 2)
        fragment = _one(session)
        assert _indices(fragment) == [2]

        assert session.receive(self._frames(_confirm(fragment[0] & 0x0F, unsolicited=True))) == b""
        assert buffers.total == 0

    def test_a_confirmation_from_another_address_confirms_nothing(self):
        session, buffers, _ = _enabled()
        _analog(buffers, 0)
        fragment = _one(session)
        control = link.control_byte(
            from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        stranger = link.build(
            control, OUTSTATION, 99, b"\xc0" + _confirm(fragment[0] & 0x0F, unsolicited=True)
        )

        session.receive(stranger)

        assert buffers.total == 1
