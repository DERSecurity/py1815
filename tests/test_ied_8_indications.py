"""IED certification procedures, sections 8.6 to 8.10.

Internal indications, time, cold restart, application layer fragmentation and
multi-drop support. Waiting, in the procedures, is done here by moving the
clock the session is given.
"""

from __future__ import annotations

import pytest
from ied_harness import (
    COLD_RESTART,
    DELAY_MEASURE,
    ERROR_IIN,
    FREEZE,
    IIN1_BROADCAST,
    IIN1_NEED_TIME,
    IIN1_RESTART,
    IIN2_BAD_FUNCTION,
    IIN2_OBJECT_UNKNOWN,
    IIN2_OVERFLOW,
    IIN2_PARAMETER,
    Q_COUNT_8,
    Q_RANGE_8,
    RECORD_CURRENT_TIME,
    WRITE,
    Dut,
    classes,
    header,
)

FREEZE_ALL = header(20, 0)


class TestRestart:
    def test_8_6_1_2_the_restart_indication_stands_until_the_master_clears_it(self):
        dut = Dut()
        dut.restart()
        assert dut.master.read(classes(1)).fragment.iin1 & IIN1_RESTART
        assert dut.master.read(classes(1)).fragment.iin1 & IIN1_RESTART, "and stands"
        cleared = dut.master.request(WRITE, header(80, 1, Q_RANGE_8, 7, 7) + b"\x00").fragment
        assert cleared.is_null
        assert not cleared.iin1 & IIN1_RESTART
        assert not dut.master.read(classes(1)).fragment.iin1 & IIN1_RESTART


class TestErrorIndications:
    def test_8_6_2_2_an_unsupported_function_code(self):
        dut = Dut()
        bad = dut.master.request(0x70, classes(0)).fragment
        assert bad.iin2 & IIN2_BAD_FUNCTION
        good = dut.master.read(classes(0)).fragment
        assert not good.iin2 & ERROR_IIN, "the indication does not linger"

    def test_8_6_3_2_an_unknown_object(self):
        dut = Dut()
        bad = dut.master.read(header(0, 0)).fragment
        assert bad.iin2 & IIN2_OBJECT_UNKNOWN
        good = dut.master.read(classes(0)).fragment
        assert not good.iin2 & ERROR_IIN


class TestBroadcast:
    def _frozen(self, dut: Dut) -> list[int]:
        return [o.value for o in dut.master.read(header(21, 0)).fragment.of(21)]

    def test_8_6_5_2_a_broadcast_is_acted_on_and_never_answered(self):
        dut = Dut()
        # First with a link confirmation asked for, which a broadcast cannot have.
        assert dut.master.request(FREEZE, FREEZE_ALL, destination=0xFFFF, control=0xF3).silent
        first = dut.master.read(classes(1)).fragment
        if not first.iin1 & IIN1_BROADCAST:
            if first.con:
                dut.master.confirm(first)
            assert dut.master.request(FREEZE, FREEZE_ALL, destination=0xFFFF).silent
            first = dut.master.read(classes(1)).fragment
        assert first.iin1 & IIN1_BROADCAST
        assert not first.iin2 & ERROR_IIN
        if first.con:
            dut.master.confirm(first)
        after = dut.master.read(classes(1)).fragment
        assert after.is_null and not after.iin1 & IIN1_BROADCAST
        assert self._frozen(dut) == [5, 5, 5], "and the freeze was carried out"

    def test_8_6_5_3_the_confirming_broadcast_address(self):
        dut = Dut()
        dut.master.empty_events()
        assert dut.master.request(FREEZE, FREEZE_ALL, destination=0xFFFE).silent
        first = dut.master.read(classes(1)).fragment
        assert not first.body and not first.is_error
        assert first.iin1 & IIN1_BROADCAST
        assert first.con, "the indication is to be confirmed"
        # Asked again before confirming: it still stands, and still asks.
        again = dut.master.read(classes(1)).fragment
        assert again.iin1 & IIN1_BROADCAST and again.con
        dut.master.confirm(again)
        after = dut.master.read(classes(1)).fragment
        assert after.is_null and not after.iin1 & IIN1_BROADCAST
        assert not after.con

    def test_8_6_5_3_the_non_confirming_broadcast_address(self):
        dut = Dut()
        dut.master.empty_events()
        assert dut.master.request(FREEZE, FREEZE_ALL, destination=0xFFFD).silent
        first = dut.master.read(classes(1)).fragment
        assert not first.body and not first.is_error
        assert first.iin1 & IIN1_BROADCAST
        assert not first.con, "no confirmation is asked for on its account"
        after = dut.master.read(classes(1)).fragment
        assert not after.iin1 & IIN1_BROADCAST, "said once, and then cleared"

    def test_8_6_5_1_a_response_that_needs_confirming_anyway_still_asks(self):
        dut = Dut()
        dut.master.empty_events()
        dut.toggle(0)
        dut.master.request(FREEZE, FREEZE_ALL, destination=0xFFFD)
        fragment = dut.master.read(classes(1)).fragment
        assert fragment.iin1 & IIN1_BROADCAST
        assert fragment.con, "for the events it carries"

    @pytest.mark.parametrize("address", [0xFFFD, 0xFFFE, 0xFFFF])
    def test_8_6_5_1_a_broadcast_read_is_not_answered(self, address):
        dut = Dut()
        assert dut.master.read(classes(0), destination=address).silent


class TestBufferOverflow:
    def test_8_6_6_2_1_binary_input_events(self):
        dut = Dut(capacity=5)
        dut.master.empty_events()
        for _ in range(5):
            dut.toggle(0)
        full = dut.master.read(classes(1)).fragment
        assert len(full.of(2)) == 5
        assert not full.iin2 & IIN2_OVERFLOW, "full, and nothing lost yet"
        # Not confirmed. One more event and something has to go.
        dut.toggle(0)
        one = dut.master.read(classes(1, qualifier=Q_COUNT_8, count=1)).fragment
        assert len(one.of(2)) == 1
        assert one.iin2 & IIN2_OVERFLOW
        dut.master.confirm(one)
        next_one = dut.master.read(classes(1, qualifier=Q_COUNT_8, count=1)).fragment
        assert len(next_one.of(2)) == 1
        assert not next_one.iin2 & IIN2_OVERFLOW, "room was made, and the master was told"
        dut.master.confirm(next_one)

    def test_8_6_6_2_2_analog_events_keep_one_per_point_so_cannot_overflow_this_way(self):
        """The procedure ends here for a device that queues one event per analog point."""
        dut = Dut(capacity=5)
        dut.master.empty_events()
        for _ in range(8):
            dut.step(0)
        fragment = dut.master.read(classes(1)).fragment
        assert len(fragment.of(32)) == 1
        assert not fragment.iin2 & IIN2_OVERFLOW


class TestTime:
    def test_8_7_1_1_2_delay_measurement(self):
        dut = Dut()
        for _ in range(3):
            fragment = dut.master.request(DELAY_MEASURE).fragment
            (delay,) = fragment.objects
            assert (delay.group, delay.variation, delay.qualifier) == (52, 2, Q_COUNT_8)
            assert 0 <= delay.value < 50, "milliseconds the request was held"
            assert not fragment.is_error

    def test_8_7_1_2_2_time_synchronization(self):
        dut = Dut(need_time=True)
        dut.restart()
        asking = dut.master.read(classes(2)).fragment
        assert asking.iin1 & IIN1_NEED_TIME
        moment = 1_800_000_000_000
        written = dut.master.request(
            WRITE, header(50, 1, Q_COUNT_8, 1) + moment.to_bytes(6, "little")
        ).fragment
        assert written.is_null
        assert not written.iin1 & IIN1_NEED_TIME
        # An event a known time later carries the written time, moved on by that much.
        dut.clock.advance(2.5)
        dut.toggle(2)
        (event,) = dut.master.read(classes(2)).fragment.of(2)
        assert event.time is not None
        assert abs(event.time - (moment + 2500)) <= 20

    def test_8_7_1_2_2_time_is_asked_for_again_after_a_restart(self):
        """The written time does not survive a restart, so the request for it returns."""
        dut = Dut(need_time=True)
        moment = 1_800_000_000_000
        time_write = header(50, 1, Q_COUNT_8, 1) + moment.to_bytes(6, "little")
        assert not dut.master.request(WRITE, time_write).fragment.iin1 & IIN1_NEED_TIME
        assert not dut.master.read(classes(0)).fragment.iin1 & IIN1_NEED_TIME
        dut.restart()
        assert dut.master.read(classes(0)).fragment.iin1 & IIN1_NEED_TIME

    def test_8_7_2_lan_time_synchronization(self):
        """Record the time by broadcast, then write when that request was sent."""
        dut = Dut(need_time=True)
        dut.restart()
        assert dut.master.read(classes(2)).fragment.iin1 & IIN1_NEED_TIME
        assert dut.master.request(RECORD_CURRENT_TIME, destination=0xFFFF).silent
        sent_at = 1_800_000_000_000
        dut.clock.advance(5.0)
        written = dut.master.request(
            WRITE, header(50, 3, Q_COUNT_8, 1) + sent_at.to_bytes(6, "little")
        ).fragment
        assert not written.body and not written.is_error
        assert written.iin1 & IIN1_BROADCAST
        assert not written.iin1 & IIN1_NEED_TIME
        if written.con:
            dut.master.confirm(written)
        dut.clock.advance(2.5)
        dut.toggle(2)
        (event,) = dut.master.read(classes(2)).fragment.of(2)
        assert (event.group, event.variation) == (2, 2), "the clock is set, so the time is absolute"
        assert abs(event.time - (sent_at + 5000 + 2500)) <= 20

    def test_8_7_2_the_time_is_recorded_for_a_request_to_this_outstation_too(self):
        dut = Dut(need_time=True)
        recorded = dut.master.request(RECORD_CURRENT_TIME).fragment
        assert recorded.is_null
        dut.clock.advance(1.0)
        sent_at = 1_800_000_000_000
        time_write = header(50, 3, Q_COUNT_8, 1) + sent_at.to_bytes(6, "little")
        assert not dut.master.request(WRITE, time_write).fragment.iin1 & IIN1_NEED_TIME
        dut.toggle(2)
        (event,) = dut.master.read(classes(2)).fragment.of(2)
        assert abs(event.time - (sent_at + 1000)) <= 20

    def test_8_7_2_a_recorded_time_is_used_once_and_is_needed(self):
        """With no request to record the time there is nothing to measure from."""
        dut = Dut(need_time=True)
        time_write = header(50, 3, Q_COUNT_8, 1) + (1_800_000_000_000).to_bytes(6, "little")
        refused = dut.master.request(WRITE, time_write).fragment
        assert refused.iin2 & IIN2_PARAMETER and refused.iin1 & IIN1_NEED_TIME
        dut.master.request(RECORD_CURRENT_TIME)
        assert not dut.master.request(WRITE, time_write).fragment.is_error
        assert dut.master.request(WRITE, time_write).fragment.iin2 & IIN2_PARAMETER

    def test_8_7_2_recording_the_time_carries_no_objects(self):
        dut = Dut(need_time=True)
        assert dut.master.request(RECORD_CURRENT_TIME, header(50, 1)).fragment.iin2 & IIN2_PARAMETER

    def test_8_7_a_device_that_never_asks_for_time_never_sets_the_indication(self):
        dut = Dut(need_time=False)
        dut.restart()
        assert not dut.master.read(classes(0)).fragment.iin1 & IIN1_NEED_TIME


class TestColdRestart:
    def test_8_8_2_cold_restart(self):
        restarts = []

        def restart() -> int:
            restarts.append(True)
            return 1500

        dut = Dut(restart_handler=restart)
        dut.clear_restart()
        assert not dut.master.read(classes(0)).fragment.iin1 & IIN1_RESTART
        fragment = dut.master.request(COLD_RESTART).fragment
        (delay,) = fragment.objects
        assert (delay.group, delay.variation) in {(52, 1), (52, 2)}
        assert delay.value == 1500
        assert restarts == [True]
        dut.clock.advance(2.0)
        assert dut.master.read(classes(0)).fragment.iin1 & IIN1_RESTART
        cleared = dut.master.request(WRITE, header(80, 1, Q_RANGE_8, 7, 7) + b"\x00").fragment
        assert cleared.is_null and not cleared.iin1 & IIN1_RESTART

    def test_8_8_2_cold_restart_disabled(self):
        dut = Dut()
        fragment = dut.master.request(COLD_RESTART).fragment
        assert fragment.iin2 & IIN2_BAD_FUNCTION
        assert not fragment.body


class TestFragmentation:
    #: Enough analog inputs that class 0 takes several fragments.
    MANY = 1500

    @pytest.mark.parametrize("size", [2048, 1100])
    def test_8_9_1_2_fir_fin_and_sequence_across_fragments(self, size):
        dut = Dut(extra_analogs=self.MANY, max_response=size)
        fragments = dut.master.poll(classes(0))
        assert len(fragments) > 2
        first, *middle, last = fragments
        assert first.fir and not first.fin
        assert all(not f.fir and not f.fin for f in middle)
        assert not last.fir and last.fin
        start = fragments[0].sequence
        assert [f.sequence for f in fragments] == [(start + n) % 16 for n in range(len(fragments))]
        assert all(len(f.octets) <= size for f in fragments)
        indices = [o.index for f in fragments for o in f.of(30)]
        assert indices == list(range(self.MANY + 4)), "every point, once, in order"

    def test_8_9_1_2_the_first_fragment_carries_the_requests_sequence_number(self):
        dut = Dut(extra_analogs=self.MANY)
        reply = dut.master.read(classes(0), sequence=11)
        assert reply.fragment.sequence == 11

    def test_8_9_1_2_a_response_that_fits_one_fragment_is_first_and_final(self):
        dut = Dut()
        fragment = dut.master.read(classes(0)).fragment
        assert fragment.fir and fragment.fin

    def test_8_9_1_2_each_fragment_is_segmented_by_the_transport_layer(self):
        dut = Dut(extra_analogs=self.MANY)
        reply = dut.master.read(classes(0))
        assert len(reply.segments) > 1
        assert reply.segments[0][1] and not reply.segments[0][0]
        assert reply.segments[-1][0] and not reply.segments[-1][1]

    def test_8_9_2_2_no_confirmation_no_next_fragment(self):
        dut = Dut(extra_analogs=self.MANY, confirm_timeout=5.0)
        first = dut.master.read(classes(0), sequence=2).fragment
        assert first.con and first.sequence == 2
        dut.clock.advance(6.0)
        assert dut.master.raw(b"").silent, "nothing follows unconfirmed"
        assert dut.master.confirm(first).silent, "and the confirmation is now too late"

    def test_8_9_2_2_a_timely_confirmation_brings_the_next_fragment(self):
        dut = Dut(extra_analogs=self.MANY, confirm_timeout=5.0)
        first = dut.master.read(classes(0), sequence=2).fragment
        dut.clock.advance(2.0)
        assert dut.master.raw(b"").silent, "not sent early"
        second = dut.master.confirm(first).fragment
        assert not second.fir and not second.fin and second.sequence == 3
        assert second.con, "a third is to follow"

    def test_8_9_2_2_a_confirmation_with_the_wrong_sequence_number(self):
        dut = Dut(extra_analogs=self.MANY, confirm_timeout=5.0)
        first = dut.master.read(classes(0), sequence=2).fragment
        second = dut.master.confirm(first).fragment
        assert dut.master.confirm_sequence((second.sequence + 5) % 16).silent
        dut.clock.advance(6.0)
        assert dut.master.raw(b"").silent
        assert dut.master.confirm(second).silent, "the right one, too late"

    def test_8_9_2_1_a_request_after_a_timeout_starts_again_from_the_beginning(self):
        dut = Dut(extra_analogs=self.MANY, confirm_timeout=5.0)
        dut.master.read(classes(0))
        dut.clock.advance(6.0)
        fragments = dut.master.poll(classes(0))
        assert fragments[0].fir and fragments[-1].fin
        assert [o.index for f in fragments for o in f.of(30)][:3] == [0, 1, 2]


class TestMultiDrop:
    @pytest.mark.parametrize("address", [1023, 1025, 3, 65519])
    def test_8_10_2_requests_to_other_stations_are_not_answered(self, address):
        dut = Dut()
        assert dut.master.read(classes(1, 2, 3), destination=address).silent

    def test_8_10_2_a_broadcast_request_is_not_answered(self):
        dut = Dut()
        assert dut.master.read(classes(1, 2, 3), destination=0xFFFF).silent

    def test_8_10_2_a_request_to_this_station_is_answered(self):
        dut = Dut()
        reply = dut.master.read(classes(1, 2, 3))
        assert reply.fragment.is_null
        assert reply.frames[0].source == 1024 and reply.frames[0].destination == 1
