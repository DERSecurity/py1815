"""Commanding this outstation: dispatch, select state, and the echo.

Driven through ``Session._handle_fragment`` rather than the link layer, because
what is under test here is which control was answered with which status, and a
frame around it adds octets without adding a case. The framing is already
pinned in ``test_session``.
"""

from __future__ import annotations

import pytest

from py1815.application import FunctionCode, IIN2Bit, QualifierCode
from py1815.control import CommandStatus, ControlRelayOutputBlock, OperationType, decode_crob
from py1815.session import Control, Session

#: LATCH_ON, count 1, 100 ms on, 200 ms off, status SUCCESS.
LATCH_ON = "030164000000c800000000"
LATCH_OFF = "040164000000c800000000"


class Commands:
    """A control provider that answers from a script and records what it saw."""

    def __init__(self, statuses: list[CommandStatus] | None = None) -> None:
        self.statuses = statuses
        self.selected: list[list[Control]] = []
        self.operated: list[list[Control]] = []

    def _answer(self, controls):
        return (
            self.statuses if self.statuses is not None else [CommandStatus.SUCCESS] * len(controls)
        )

    def select(self, controls):
        self.selected.append(list(controls))
        return self._answer(controls)

    def operate(self, controls):
        self.operated.append(list(controls))
        return self._answer(controls)


class Reader:
    def read(self, headers):
        return b""


def _session(commands: Commands | None = None, **kwargs) -> tuple[Session, Commands]:
    provider = commands if commands is not None else Commands()
    clock = kwargs.pop("clock", None)
    session = Session(
        Reader(),
        control_provider=provider,
        clock=clock or (lambda: 0.0),
        **kwargs,
    )
    return session, provider


def _request(function: FunctionCode, *controls: tuple[int, int, int, str]) -> bytes:
    """One control request: a header per group run, each object behind its index."""
    body = b""
    run: list[tuple[int, str]] = []
    group = variation = -1
    for grp, var, index, octets in controls:
        if (grp, var) != (group, variation):
            if run:
                body += _block(group, variation, run)
            group, variation, run = grp, var, []
        run.append((index, octets))
    body += _block(group, variation, run)
    return bytes([0xC0, function]) + body


def _block(group: int, variation: int, run: list[tuple[int, str]]) -> bytes:
    header = bytes([group, variation, QualifierCode.UINT8_COUNT_UINT8_INDEX, len(run)])
    return header + b"".join(bytes([i]) + bytes.fromhex(o) for i, o in run)


def _statuses(response: bytes) -> list[CommandStatus]:
    """Every control status in a response, in order, however it is blocked."""
    out: list[CommandStatus] = []
    offset = 4  # application header plus IIN
    while offset < len(response):
        group, _variation, _qualifier, count = response[offset : offset + 4]
        offset += 4
        for _ in range(count):
            offset += 1  # index
            assert group == 12, "only CROB blocks are decoded here"
            out.append(decode_crob(response[offset : offset + 11]).status)
            offset += 11
    return out


class TestWithoutAControlProvider:
    """The monitor outstation, which is what this was until now."""

    @pytest.mark.parametrize(
        "function",
        [FunctionCode.SELECT, FunctionCode.OPERATE, FunctionCode.DIRECT_OPERATE],
    )
    def test_a_control_is_still_refused_as_unsupported(self, function):
        session = Session(Reader())

        response = session._handle_fragment(_request(function, (12, 1, 0, LATCH_ON)))

        assert response[3] & IIN2Bit.FUNC_NOT_SUPPORTED

    def test_direct_operate_no_ack_is_still_dropped(self):
        session = Session(Reader())

        assert (
            session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE_NR, (12, 1, 0, LATCH_ON)))
            == b""
        )


class TestDirectOperate:
    def test_the_control_reaches_the_provider_with_its_index(self):
        session, commands = _session()

        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE, (12, 1, 7, LATCH_ON)))

        (control,) = commands.operated[0]
        assert control.index == 7
        assert control.group == 12
        assert isinstance(control.command, ControlRelayOutputBlock)
        assert control.command.operation is OperationType.LATCH_ON

    def test_the_response_echoes_one_status_per_object(self):
        """D14. Four points where one is unsupported returns four objects."""
        commands = Commands(
            [
                CommandStatus.SUCCESS,
                CommandStatus.NOT_SUPPORTED,
                CommandStatus.SUCCESS,
                CommandStatus.OUT_OF_RANGE,
            ]
        )
        session, _ = _session(commands)

        response = session._handle_fragment(
            _request(
                FunctionCode.DIRECT_OPERATE,
                (12, 1, 0, LATCH_ON),
                (12, 1, 1, LATCH_ON),
                (12, 1, 2, LATCH_ON),
                (12, 1, 3, LATCH_ON),
            )
        )

        assert _statuses(response) == [
            CommandStatus.SUCCESS,
            CommandStatus.NOT_SUPPORTED,
            CommandStatus.SUCCESS,
            CommandStatus.OUT_OF_RANGE,
        ]

    def test_a_provider_answering_the_wrong_number_is_a_programming_error(self):
        session, _ = _session(Commands([CommandStatus.SUCCESS]))

        with pytest.raises(ValueError, match="answered 1 of 2"):
            session._handle_fragment(
                _request(FunctionCode.DIRECT_OPERATE, (12, 1, 0, LATCH_ON), (12, 1, 1, LATCH_ON))
            )


class TestSelectBeforeOperate:
    def test_a_matching_operate_reaches_the_provider(self):
        session, commands = _session()
        request = _request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON))

        session._handle_fragment(request)
        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert len(commands.operated) == 1
        assert _statuses(response) == [CommandStatus.SUCCESS]

    def test_a_select_alone_operates_nothing(self):
        session, commands = _session()

        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))

        assert commands.selected and not commands.operated

    def test_an_operate_with_no_select_is_refused(self):
        session, commands = _session()

        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert _statuses(response) == [CommandStatus.NO_SELECT]
        assert not commands.operated

    def test_an_operate_naming_something_else_is_refused(self):
        session, commands = _session()
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))

        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_OFF)))

        assert _statuses(response) == [CommandStatus.NO_SELECT]
        assert not commands.operated

    def test_a_mismatched_operate_leaves_the_select_armed(self):
        """D12 spends a select on the operate that matches it. A master that
        sent the wrong one still holds the reservation it was granted."""
        session, commands = _session()
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))
        session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_OFF)))

        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert _statuses(response) == [CommandStatus.SUCCESS]
        assert len(commands.operated) == 1

    def test_a_matching_operate_spends_the_select(self):
        session, _ = _session()
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))
        session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        again = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert _statuses(again) == [CommandStatus.NO_SELECT]

    def test_an_expired_select_is_a_timeout_rather_than_a_refusal(self):
        """The two are different: a master that was too slow learns that it was
        too slow, rather than that it never selected."""
        now = [0.0]
        session, commands = _session(clock=lambda: now[0], select_timeout=10.0)
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))

        now[0] = 10.5
        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert _statuses(response) == [CommandStatus.TIMEOUT]
        assert not commands.operated

    def test_a_select_inside_the_window_still_operates(self):
        now = [0.0]
        session, _ = _session(clock=lambda: now[0], select_timeout=10.0)
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))

        now[0] = 9.9
        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert _statuses(response) == [CommandStatus.SUCCESS]

    def test_a_second_select_replaces_the_first(self):
        session, _ = _session()
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 5, LATCH_ON)))

        stale = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))
        fresh = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 5, LATCH_ON)))

        assert _statuses(stale) == [CommandStatus.NO_SELECT]
        assert _statuses(fresh) == [CommandStatus.SUCCESS]

    def test_a_reconnect_discards_the_select(self):
        """D12. A reservation held for an operate on a socket that died must not
        be honoured over the connection that replaced it."""
        session, commands = _session()
        session._handle_fragment(_request(FunctionCode.SELECT, (12, 1, 0, LATCH_ON)))

        session.connection_reset()
        response = session._handle_fragment(_request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON)))

        assert _statuses(response) == [CommandStatus.NO_SELECT]
        assert not commands.operated

    def test_a_partly_refused_select_still_arms_the_whole_request(self):
        """D16. The operate a master sends next is the request it already sent,
        so matching against the subset that succeeded would reject it."""
        commands = Commands([CommandStatus.SUCCESS, CommandStatus.NOT_SUPPORTED])
        session, _ = _session(commands)
        both = ((12, 1, 0, LATCH_ON), (12, 1, 1, LATCH_ON))

        session._handle_fragment(_request(FunctionCode.SELECT, *both))
        response = session._handle_fragment(_request(FunctionCode.OPERATE, *both))

        assert _statuses(response) == [CommandStatus.SUCCESS, CommandStatus.NOT_SUPPORTED]
        assert len(commands.operated) == 1


class TestDirectOperateNoAck:
    """Table 4-2: same as function code 5, but silent. Both halves matter."""

    def test_it_executes(self):
        session, commands = _session()

        session._handle_fragment(_request(FunctionCode.DIRECT_OPERATE_NR, (12, 1, 3, LATCH_ON)))

        assert len(commands.operated) == 1
        assert commands.operated[0][0].index == 3

    def test_it_answers_nothing(self):
        session, _ = _session()

        response = session._handle_fragment(
            _request(FunctionCode.DIRECT_OPERATE_NR, (12, 1, 3, LATCH_ON))
        )

        assert response == b""

    def test_an_unreadable_one_stays_silent_and_executes_nothing(self):
        """Silence is owed to the function code, not to the request parsing."""
        session, commands = _session()
        truncated = _request(FunctionCode.DIRECT_OPERATE_NR, (12, 1, 3, LATCH_ON))[:-4]

        assert session._handle_fragment(truncated) == b""
        assert not commands.operated

    #: Two is where the application header ends; eighteen is the whole request.
    @pytest.mark.parametrize("length", range(2, 19))
    def test_no_body_length_draws_a_reply(self, length):
        """The criterion the plan states separately from the fuzzing above,
        because the two contradict each other: every other control function must
        answer whatever arrives, and this one must answer none of it. A master
        that asked for no response is not listening for a parse error either."""
        session, _ = _session()
        full = _request(FunctionCode.DIRECT_OPERATE_NR, (12, 1, 3, LATCH_ON))

        assert session._handle_fragment(full[:length]) == b""

    def test_only_the_complete_one_executes(self):
        session, commands = _session()
        full = _request(FunctionCode.DIRECT_OPERATE_NR, (12, 1, 3, LATCH_ON))

        for length in range(2, len(full)):
            session._handle_fragment(full[:length])
        assert not commands.operated

        session._handle_fragment(full)
        assert len(commands.operated) == 1

    @pytest.mark.parametrize(
        "function",
        [
            FunctionCode.IMMED_FREEZE_NR,
            FunctionCode.FREEZE_CLEAR_NR,
            FunctionCode.FREEZE_AT_TIME_NR,
        ],
    )
    def test_the_other_silent_functions_are_still_dropped_unexecuted(self, function):
        session, commands = _session()

        assert session._handle_fragment(bytes([0xC0, function])) == b""
        assert not commands.operated


class TestAFragmentThatDoesNotParse:
    """D15. A per-object status has to be attached to an object."""

    def test_a_truncated_body_is_refused_at_the_fragment(self):
        session, commands = _session()
        truncated = _request(FunctionCode.DIRECT_OPERATE, (12, 1, 0, LATCH_ON))[:-4]

        response = session._handle_fragment(truncated)

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert not commands.operated

    def test_an_unknown_control_group_is_refused_at_the_fragment(self):
        session, commands = _session()

        response = session._handle_fragment(
            _request(FunctionCode.DIRECT_OPERATE, (99, 1, 0, LATCH_ON))
        )

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert not commands.operated


class TestTheEchoMirrorsTheRequest:
    def test_two_groups_come_back_as_two_blocks(self):
        session, _ = _session()

        response = session._handle_fragment(
            _request(
                FunctionCode.DIRECT_OPERATE,
                (12, 1, 0, LATCH_ON),
                (41, 2, 4, "e80300"),
            )
        )

        body = response[4:]
        assert body[0] == 12 and body[1] == 1
        second = 4 + 1 + 11
        assert body[second] == 41 and body[second + 1] == 2


def _two_headers(function: FunctionCode) -> bytes:
    """One request, two headers, both naming group 12 variation 1."""
    header = bytes([12, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 1])
    crob = bytes.fromhex(LATCH_ON)
    return bytes([0xC0, function]) + header + bytes([0]) + crob + header + bytes([5]) + crob


class TestTheEchoKeepsTheRequestsHeaderBoundaries:
    """Splitting on the group would merge two headers into one block carrying
    twice the count -- a tidier response than the request, and not the request.
    """

    def test_two_headers_naming_one_group_come_back_as_two_blocks(self):
        session, _ = _session()

        body = session._handle_fragment(_two_headers(FunctionCode.DIRECT_OPERATE))[4:]

        assert body[:3] == bytes([12, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX])
        assert body[3] == 1, "the first block answers one object, not two"
        second = 4 + 1 + 11
        assert body[second : second + 3] == bytes([12, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX])
        assert body[second + 3] == 1

    def test_both_controls_are_still_answered(self):
        session, commands = _session()

        session._handle_fragment(_two_headers(FunctionCode.DIRECT_OPERATE))

        assert [c.index for c in commands.operated[0]] == [0, 5]

    def test_re_blocking_does_not_invalidate_a_select(self):
        """The block is framing, not instruction. An operate carrying the same
        objects under a different header boundary asks for the same points."""
        session, commands = _session()
        session._handle_fragment(_two_headers(FunctionCode.SELECT))

        merged = _request(FunctionCode.OPERATE, (12, 1, 0, LATCH_ON), (12, 1, 5, LATCH_ON))
        response = session._handle_fragment(merged)

        assert _statuses(response) == [CommandStatus.SUCCESS, CommandStatus.SUCCESS]
        assert len(commands.operated) == 1


class TestTheProviderContractHoldsOnEveryPath:
    @pytest.mark.parametrize(
        "function",
        [
            FunctionCode.SELECT,
            FunctionCode.DIRECT_OPERATE,
            FunctionCode.DIRECT_OPERATE_NR,
        ],
    )
    def test_a_miscounted_answer_is_a_programming_error(self, function):
        """Answering nothing is not a reason to hold a path to a weaker
        contract than the one beside it."""
        session, _ = _session(Commands([CommandStatus.SUCCESS]))

        with pytest.raises(ValueError, match="answered 1 of 2"):
            session._handle_fragment(_request(function, (12, 1, 0, LATCH_ON), (12, 1, 1, LATCH_ON)))

    def test_the_operate_after_select_path_is_checked_too(self):
        """Needs a provider that selects correctly and miscounts the operate,
        or the select raises first and the path under test is never reached."""

        class SelectsWellOperatesBadly(Commands):
            def operate(self, controls):
                self.operated.append(list(controls))
                return [CommandStatus.SUCCESS]

        session, _ = _session(SelectsWellOperatesBadly())
        both = ((12, 1, 0, LATCH_ON), (12, 1, 1, LATCH_ON))
        session._handle_fragment(_request(FunctionCode.SELECT, *both))

        with pytest.raises(ValueError, match="answered 1 of 2"):
            session._handle_fragment(_request(FunctionCode.OPERATE, *both))
