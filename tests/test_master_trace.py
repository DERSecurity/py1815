"""The record of an exchange: frames, with what each one says."""

from __future__ import annotations

from py1815 import link
from py1815.application import IIN, FunctionCode, build_request
from py1815.master import MasterAssociation
from py1815.master import requests as rq
from py1815.master.trace import RECEIVED, SENT, Trace, iin_names
from py1815.transport import segment

OUTSTATION, MASTER = 1024, 1


class Clock:
    def __init__(self) -> None:
        self.now = 50.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def _from_outstation(fragment: bytes) -> bytes:
    control = link.control_byte(
        from_master=False, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    return b"".join(link.build(control, MASTER, OUTSTATION, tpdu) for tpdu in segment(fragment))


class TestWhatAFrameSays:
    def test_a_request_is_read_down_to_what_it_asks_for(self):
        trace = Trace(clock=Clock())
        octets = MasterAssociation().request(FunctionCode.READ, rq.scan("integrity"))

        (entry,) = trace.record(SENT, octets)

        assert (entry.id, entry.direction, entry.at) == (1, "tx", 51.0)
        assert entry.octets == octets
        assert entry.link == {
            "from_master": True,
            "primary": True,
            "function": "UNCONFIRMED_USER_DATA",
            "destination": OUTSTATION,
            "source": MASTER,
            "user_data": 15,
        }
        assert entry.transport == {"fir": True, "fin": True, "sequence": 0}
        assert entry.application["function"] == "READ"
        assert entry.application["objects"] == ["class 1", "class 2", "class 3", "class 0"]
        assert entry.summary == "READ seq 0: class 1, class 2, class 3, class 0"

    def test_a_read_of_named_points_lists_them(self):
        trace = Trace()
        octets = MasterAssociation().request(
            FunctionCode.READ, bytes.fromhex("1E 00 17 03 04 06 08 01 00 06 1E 02 00 02 05")
        )
        (entry,) = trace.record(SENT, octets)
        assert entry.application["objects"] == ["g30v0 [4, 6, 8]", "g1v0 all", "g30v2 2..5"]

    def test_a_response_is_read_as_indications_and_objects_by_group(self):
        trace = Trace()
        fragment = bytes.fromhex("E3 81 90 00  01 02 00 00 01 81 01  1E 02 00 00 00 01 2C 01")
        (entry,) = trace.record(RECEIVED, _from_outstation(fragment))
        assert entry.direction == "rx"
        assert entry.application["iin"] == ["NEED_TIME", "DEVICE_RESTART"]
        assert entry.application["objects"] == ["g1v2 x2", "g30v2 x1"]
        assert entry.summary == (
            "RESPONSE seq 3 CON [NEED_TIME, DEVICE_RESTART]: g1v2 x2, g30v2 x1"
        )

    def test_objects_that_cannot_be_read_are_said_to_be(self):
        trace = Trace()
        (entry,) = trace.record(
            RECEIVED, _from_outstation(bytes.fromhex("C0 81 00 00 6E 04 00 00 00 41"))
        )
        assert "group 110" in entry.application["problem"]

    def test_a_confirmation_and_a_link_frame(self):
        trace = Trace()
        association = MasterAssociation()
        association.request(FunctionCode.READ, rq.scan("class1"))
        reply = association.receive(_from_outstation(bytes.fromhex("E0 81 00 00")))
        (confirm,) = trace.record(SENT, reply)
        assert confirm.summary == "CONFIRM seq 0"

        control = link.control_byte(
            from_master=False, primary=True, function=link.PrimaryFunction.REQUEST_LINK_STATUS
        )
        (status,) = trace.record(RECEIVED, link.build(control, MASTER, OUTSTATION))
        assert status.summary == "REQUEST_LINK_STATUS"
        assert status.transport is None and status.application is None

    def test_a_fragment_across_frames_is_read_on_the_frame_that_completes_it(self):
        trace = Trace()
        body = b"".join(bytes([30, 2, 0, index, index, 1, index, 0]) for index in range(60))
        fragment = bytes.fromhex("C0 81 00 00") + body
        entries = trace.record(RECEIVED, _from_outstation(fragment))
        assert len(entries) > 1
        assert all(entry.application is None for entry in entries[:-1])
        assert entries[0].summary == "segment 0 of a fragment still arriving"
        assert entries[-1].application["objects"] == ["g30v2 x60"]
        assert entries[-1].transport["fin"] and not entries[-1].transport["fir"]

    def test_a_frame_is_recorded_when_its_last_octet_arrives(self):
        trace = Trace()
        octets = _from_outstation(bytes.fromhex("C0 81 00 00"))
        assert trace.record(RECEIVED, octets[:6]) == []
        (entry,) = trace.record(RECEIVED, octets[6:])
        assert entry.octets == octets


class TestKeeping:
    def _request(self, sequence: int) -> bytes:
        control = link.control_byte(
            from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
        )
        fragment = build_request(FunctionCode.READ, sequence=sequence, body=rq.scan("class0"))
        return link.build(control, OUTSTATION, MASTER, b"\xc0" + fragment)

    def test_ids_count_up_and_frames_are_read_since_one(self):
        trace = Trace()
        for sequence in range(3):
            trace.record(SENT, self._request(sequence))
        assert [entry.id for entry in trace.since()] == [1, 2, 3]
        assert [entry.id for entry in trace.since(2)] == [3]
        assert len(trace) == 3

    def test_the_oldest_are_dropped_past_the_capacity(self):
        trace = Trace(capacity=2)
        for sequence in range(3):
            trace.record(SENT, self._request(sequence))
        assert [entry.id for entry in trace.since()] == [2, 3]

    def test_clearing_forgets_the_frames_and_not_the_count(self):
        trace = Trace()
        trace.record(SENT, self._request(0))
        trace.clear()
        assert trace.since() == [] and len(trace) == 0
        (entry,) = trace.record(SENT, self._request(1))
        assert entry.id == 2

    def test_a_listener_is_called_with_each_frame(self):
        trace, heard = Trace(), []
        trace.listeners.append(heard.append)
        recorded = trace.record(SENT, self._request(0))
        assert heard == recorded

    def test_a_new_connection_forgets_half_a_frame(self):
        trace = Trace()
        trace.record(RECEIVED, _from_outstation(bytes.fromhex("C0 81 00 00"))[:6])
        trace.reset()
        (entry,) = trace.record(RECEIVED, _from_outstation(bytes.fromhex("C1 81 00 00")))
        assert entry.application["sequence"] == 1


def test_indications_are_named_first_octet_first():
    assert iin_names(IIN(0x90, 0x04)) == ["NEED_TIME", "DEVICE_RESTART", "PARAM_ERROR"]
    assert iin_names(IIN()) == []
