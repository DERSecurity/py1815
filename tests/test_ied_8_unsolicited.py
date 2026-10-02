"""IED certification procedures, section 8.11: unsolicited responses.

Support for unsolicited responses is optional at subset levels 1 and 2, and a
session has them only when it is built with them on. The procedures for a
device configured with them on are carried out here against that
configuration; section 8.11.2.6, the same device with them configured off, is
carried out against the default, which is how every other test file builds
its device.

Waiting, in the procedures, is moving the clock the session is given, and
watching the line is `TestMaster.listen`, which asks the session for what it
would send. Over a socket the listener does the asking; see
`test_server_unsolicited.py`.

One reading of the procedures is worth stating. Section 8.11.2.1 has a
class 0 read issued while the initial null response is still unconfirmed and
checks that it is answered. The standard, as amended by TB2015-002a, has an
outstation hold any read while an unsolicited response awaits confirmation,
the initial null response included, and answer it when the confirmation
arrives or its time runs out. This device does that, so the read in that
step is answered when the null response's confirmation timeout comes round,
which is within the step's wait.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    DISABLE_UNSOLICITED,
    ENABLE_UNSOLICITED,
    ERROR_IIN,
    IIN1_RESTART,
    IIN2_BAD_FUNCTION,
    MASTER,
    Q_RANGE_8,
    RESPONSE,
    UNSOLICITED_RESPONSE,
    WRITE,
    Dut,
    Fragment,
    TestMaster,
    classes,
    header,
)

#: The confirmation timeout the procedures set for the test: five seconds.
TIMEOUT = 5.0

#: Which binary input of the device under test is in which class.
INPUT_IN_CLASS = {1: 0, 2: 2, 3: 3}

ALL_CLASSES = classes(1, 2, 3)
CLEAR_RESTART = header(80, 1, Q_RANGE_8, 7, 7) + b"\x00"


def _dut(**options) -> Dut:
    options.setdefault("unsolicited", True)
    options.setdefault("unsolicited_confirm_timeout", TIMEOUT)
    return Dut(**options)


def _heard(dut: Dut) -> list[Fragment]:
    return dut.master.listen().fragments


def _unsolicited(dut: Dut) -> Fragment:
    (fragment,) = _heard(dut)
    assert fragment.function == UNSOLICITED_RESPONSE
    return fragment


def _wait(dut: Dut, seconds: float) -> list[Fragment]:
    """Wait, watching the line, and return everything sent meanwhile."""
    heard: list[Fragment] = []
    start, steps = dut.clock.seconds, round(seconds * 10)
    for step in range(1, steps + 1):
        # Set rather than added to, so that the wait ends at exactly the
        # time asked for and not a rounding error short of it.
        dut.clock.seconds = start + seconds * step / steps
        heard += _heard(dut)
    return heard


def _in_range(fragment: Fragment) -> bool:
    """Unsolicited sequence numbers are the ones with the unsolicited bit: 16 to 31."""
    return 16 <= (fragment.octets[0] & 0x1F) <= 31


def _ready(dut: Dut) -> None:
    """Past startup: the null response confirmed and the restart cleared."""
    null = _unsolicited(dut)
    dut.master.confirm_unsolicited(null.sequence)
    dut.clear_restart()
    assert _heard(dut) == []


def _enable_all(dut: Dut) -> None:
    fragment = dut.master.request(ENABLE_UNSOLICITED, ALL_CLASSES).fragment
    assert fragment.is_null


def _binary_indices(fragment: Fragment) -> list[int]:
    return [obj.index for obj in fragment.of(2) if obj.index is not None]


# --------------------------------------------- 8.11.2.1 configuration, startup


class TestConfigurationAndStartup:
    def test_8_11_2_1_steps_1_to_3_mode_and_timeout_are_configured(self):
        assert Dut().session.facts.unsolicited is False, "off unless configured on"
        facts = _dut().session.facts
        assert facts.unsolicited is True
        assert facts.unsolicited_confirm_timeout == TIMEOUT
        assert _dut(unsolicited_confirm_timeout=1.0).session.facts.unsolicited_confirm_timeout == 1
        assert _dut(unsolicited_confirm_timeout=60.0).session.facts.unsolicited_confirm_timeout

    def test_8_11_2_1_steps_4_to_9_it_goes_to_the_configured_master(self):
        for address in (MASTER, 7):
            dut = _dut(master_address=address)
            dut.master = TestMaster(dut.session, master=address)
            dut.restart()
            dut.master = TestMaster(dut.session, master=address)

            reply = dut.master.listen()

            assert [frame.destination for frame in reply.frames] == [address]
            assert reply.fragment.function == UNSOLICITED_RESPONSE

    def test_8_11_2_1_steps_10_to_30_the_initial_null_response(self):
        dut = _dut()
        dut.restart()

        # 10 to 14: restart set, null, confirmation asked for, sequence in range.
        first = _unsolicited(dut)
        assert first.iin1 & IIN1_RESTART
        assert not first.body
        assert first.con and first.uns
        assert _in_range(first)

        # 15 to 18: two or more in ten seconds, one every five.
        assert _wait(dut, 4.9) == []
        dut.clock.advance(0.1)
        second = _unsolicited(dut)
        assert _wait(dut, 4.9) == []
        dut.clock.advance(0.1)
        third = _unsolicited(dut)
        for fragment in (second, third):
            assert fragment.iin1 & IIN1_RESTART and not fragment.body and fragment.con

        # 19 to 22: the restart is cleared, and the next one says so.
        cleared = dut.master.request(WRITE, CLEAR_RESTART).fragment
        assert cleared.is_null and not cleared.iin1 & IIN1_RESTART
        heard = _wait(dut, 5.0)
        assert len(heard) == 1 and heard[0].function == UNSOLICITED_RESPONSE
        assert not heard[0].iin1 & IIN1_RESTART

        # 23 to 25: a class 0 read is answered, within the wait, and the null
        # response goes on. The read is held while the null response awaits
        # confirmation, as the standard has it, and answered when its timeout
        # comes round.
        reply = dut.master.read(classes(0))
        heard = reply.fragments + _wait(dut, 5.0)
        answers = [f for f in heard if f.function == RESPONSE]
        assert len(answers) == 1 and answers[0].of(30), "class 0 data"
        assert any(f.function == UNSOLICITED_RESPONSE for f in heard)

        # 26 and 27: a confirmation under the wrong sequence confirms nothing.
        latest = [f for f in heard if f.function == UNSOLICITED_RESPONSE][-1]
        dut.master.confirm_unsolicited((latest.sequence + 1) % 16)
        again = _wait(dut, 5.0)
        assert [f.function for f in again] == [UNSOLICITED_RESPONSE]

        # 28 to 30: the right one does, and events generated now are not sent:
        # no class has been enabled.
        dut.master.confirm_unsolicited(again[0].sequence)
        dut.toggle(0)
        dut.toggle(2)
        assert _wait(dut, 6.0) == []


# ------------------------------------------- 8.11.2.2 to 8.11.2.4 class data


class TestClassData:
    @pytest.mark.parametrize("number", [1, 2, 3])
    def test_8_11_2_2_to_4_unsolicited_responses_for_one_class(self, number):
        dut = _dut()
        _ready(dut)

        # 1 and 2: disable every class.
        assert dut.master.request(DISABLE_UNSOLICITED, ALL_CLASSES).fragment.is_null

        # 3 and 4: an event of the class is kept, and not sent.
        point = INPUT_IN_CLASS[number]
        dut.toggle(point)
        assert _wait(dut, 6.0) == []

        # 5 and 6: enable the class.
        assert dut.master.request(ENABLE_UNSOLICITED, classes(number)).fragment.is_null

        # 8 to 10: it is sent, asking to be confirmed, in range.
        first = _unsolicited(dut)
        assert first.con and first.uns and _in_range(first)
        assert point in _binary_indices(first)

        # 11 and 12: unconfirmed, it is sent again with at least the same events.
        retry = _wait(dut, TIMEOUT)
        assert len(retry) == 1
        assert set(_binary_indices(first)) <= set(_binary_indices(retry[0]))

        # 13 and 14: a confirmation under the wrong sequence changes nothing.
        dut.master.confirm_unsolicited((retry[0].sequence + 1) % 16)
        another = _wait(dut, TIMEOUT)
        assert len(another) == 1
        assert set(_binary_indices(first)) <= set(_binary_indices(another[0]))

        # 15: the right one ends it.
        dut.master.confirm_unsolicited(another[0].sequence)

        # 16 and 17: events of the other classes are not sent.
        for other in {1, 2, 3} - {number}:
            dut.toggle(INPUT_IN_CLASS[other])
        assert _wait(dut, 6.0) == []


# ------------------------------------------ 8.11.2.5 unsolicited and polled


class TestUnsolicitedAndPolled:
    def _reporting(self) -> Dut:
        dut = _dut()
        _ready(dut)
        _enable_all(dut)
        return dut

    def test_8_11_2_5_1_transmits_data_filled_unsolicited_responses(self):
        dut = self._reporting()

        dut.toggle(0)

        fragment = _unsolicited(dut)
        assert fragment.con
        assert _binary_indices(fragment) == [0]

    def test_8_11_2_5_2_clears_transmitted_data_upon_confirmation(self):
        dut = self._reporting()
        dut.toggle(0)
        fragment = _unsolicited(dut)

        dut.master.confirm_unsolicited(fragment.sequence)

        polled = dut.master.read(ALL_CLASSES).fragment
        assert _binary_indices(polled) == []

    def test_8_11_2_5_3_processes_non_read_requests_immediately(self):
        dut = self._reporting()
        dut.toggle(0)
        first = _unsolicited(dut)

        reply = dut.master.request(WRITE, CLEAR_RESTART)

        assert reply.fragment.function == RESPONSE and not reply.fragment.iin2 & ERROR_IIN
        retry = _wait(dut, TIMEOUT)
        assert [f.function for f in retry] == [UNSOLICITED_RESPONSE]
        assert set(_binary_indices(first)) <= set(_binary_indices(retry[0]))

    def test_8_11_2_5_4_defers_read_requests_until_after_confirmation_received(self):
        dut = self._reporting()
        dut.toggle(0)
        first = _unsolicited(dut)

        assert dut.master.read(ALL_CLASSES).silent
        assert _wait(dut, TIMEOUT - 0.5) == [], "no answer before the timeout"

        answer = dut.master.confirm_unsolicited(first.sequence).fragment
        assert answer.function == RESPONSE, "answered at once"
        assert _binary_indices(answer) == []
        if answer.con:
            dut.master.confirm(answer)

    def test_8_11_2_5_5_defers_read_requests_until_after_confirmation_timeout(self):
        dut = self._reporting()
        dut.toggle(0)
        first = _unsolicited(dut)

        assert dut.master.read(ALL_CLASSES).silent
        assert _wait(dut, TIMEOUT - 0.1) == []
        dut.clock.advance(0.1)
        (answer,) = _heard(dut)

        assert answer.function == RESPONSE, "a polled response, not an unsolicited one"
        assert set(_binary_indices(first)) <= set(_binary_indices(answer))
        assert answer.con
        dut.master.confirm(answer)
        assert _wait(dut, 6.0) == []

    def test_8_11_2_5_6_abandons_read_requests_upon_subsequent_non_read_requests(self):
        dut = self._reporting()
        dut.toggle(0)
        first = _unsolicited(dut)
        assert dut.master.read(ALL_CLASSES).silent

        reply = dut.master.request(WRITE, CLEAR_RESTART)

        assert reply.fragment.function == RESPONSE and not reply.fragment.iin2 & ERROR_IIN
        heard = _wait(dut, TIMEOUT)
        assert [f.function for f in heard] == [UNSOLICITED_RESPONSE], "and no read answered"
        assert set(_binary_indices(first)) <= set(_binary_indices(heard[0]))

    def test_8_11_2_5_7_abandons_read_requests_upon_subsequent_read_requests(self):
        dut = self._reporting()
        dut.toggle(0)
        first = _unsolicited(dut)
        assert dut.master.read(classes(0)).silent
        assert dut.master.read(ALL_CLASSES).silent

        assert _wait(dut, TIMEOUT - 0.1) == []
        dut.clock.advance(0.1)
        (answer,) = _heard(dut)

        assert answer.function == RESPONSE
        assert not answer.of(30) and not answer.of(1), "the class 1 to 3 read's answer"
        assert set(_binary_indices(first)) <= set(_binary_indices(answer))
        assert answer.con
        dut.master.confirm(answer)
        assert _wait(dut, 6.0) == []

    def test_8_11_2_5_8_inhibits_unsolicited_responses_until_after_polled_confirmation(self):
        dut = self._reporting()
        # The window between an event and its unsolicited response is until
        # the session is next asked; the read arrives inside it.
        dut.toggle(0)
        polled = dut.master.read(ALL_CLASSES).fragment
        assert _binary_indices(polled) == [0]
        assert polled.con

        dut.toggle(1)
        assert _wait(dut, 9.9) == [], "nothing within the confirmation timeout"
        dut.clock.advance(0.1)
        fragment = _unsolicited(dut)

        assert {0, 1} <= set(_binary_indices(fragment))
        assert fragment.con
        dut.master.confirm_unsolicited(fragment.sequence)
        assert dut.outstation.events.total == 0

    def test_8_11_2_5_9_retries_a_configurable_number_of_times(self):
        # 1 to 10: five retries, and then no more.
        dut = _dut(unsolicited_retries=5, unsolicited_resume=None)
        dut.restart()
        _ready(dut)
        _enable_all(dut)
        dut.toggle(0)
        first = _unsolicited(dut)
        heard = _wait(dut, 20 * TIMEOUT)
        assert len(heard) == 5
        assert all(set(_binary_indices(first)) <= set(_binary_indices(f)) for f in heard)

        # 11 to 18: a confirmation after a retry ends the retries.
        dut.restart()
        _ready(dut)
        _enable_all(dut)
        dut.toggle(1)
        _unsolicited(dut)
        retry = _wait(dut, TIMEOUT)
        assert len(retry) == 1
        dut.master.confirm_unsolicited(retry[0].sequence)
        assert _wait(dut, 10 * TIMEOUT) == []

        # 19 to 28: without limit, they go on.
        dut = _dut(unsolicited_retries=None)
        dut.restart()
        _ready(dut)
        _enable_all(dut)
        dut.toggle(0)
        _unsolicited(dut)
        assert len(_wait(dut, 60 * TIMEOUT)) == 60


# ---------------------------------------------------- 8.11.2.6 configured off


class TestConfiguredOff:
    def test_8_11_2_6_steps_1_to_13_nothing_is_sent_and_enable_is_refused(self):
        dut = Dut()
        dut.restart()

        # 1 to 6: no initial response, before or after the restart is cleared.
        assert _wait(dut, 10.0) == []
        cleared = dut.master.request(WRITE, CLEAR_RESTART).fragment
        assert cleared.is_null and not cleared.iin1 & IIN1_RESTART
        assert _wait(dut, 10.0) == []

        # 7 to 10: events are reported when polled and never unasked.
        dut.master.empty_events()
        dut.toggle(0)
        dut.toggle(2)
        assert _wait(dut, 10.0) == []

        # 11 to 13: enabling is refused as a function not supported.
        refused = dut.master.request(ENABLE_UNSOLICITED, ALL_CLASSES).fragment
        assert refused.iin2 & IIN2_BAD_FUNCTION and not refused.body
        assert _wait(dut, 10.0) == []

        # Steps 14 and 15 expect the disable request refused as well. It is
        # agreed to instead (D21): a device that sends none is already in the
        # state it asks for. The catalog records this as a departure.
        agreed = dut.master.request(DISABLE_UNSOLICITED, ALL_CLASSES).fragment
        assert not agreed.iin2 & IIN2_BAD_FUNCTION
