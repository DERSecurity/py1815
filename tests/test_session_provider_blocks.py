"""A provider that says where its objects end, and static data that splits.

Section 5b of the fragmentation plan, and D35. `ReadProvider` keeps `read`,
which answers in octets and is the contract. Beside it a provider may implement
`read_blocks`, and its static data is then spread across the fragments of a
response instead of having to fit one.

The limit that lifts is not hypothetical: a class 0 poll over roughly 290
analog points already exceeds the 2,048 octets a master typically advertises.
"""

from __future__ import annotations

import pytest

from py1815.application import FunctionCode, IIN2Bit, QualifierCode
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint
from py1815.session import Session

FIN_MASK = 0x40

CLASS_0 = bytes([0xC0, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS])
INTEGRITY = bytes([0xC0, FunctionCode.READ, 60, 2, 0x06, 60, 1, 0x06])


def _block(index: int, octets: int) -> bytes:
    """One object block, distinguishable from its neighbours by its filler."""
    return bytes([30, 1, 0x00, index, index]) + bytes([index & 0xFF]) * octets


class Octets:
    """The provider this library has always had: one opaque body."""

    def __init__(self, blocks: list[bytes]) -> None:
        self.body = b"".join(blocks)

    def read(self, headers):
        return self.body


class Blocks:
    """A provider that says where its objects end."""

    def __init__(self, blocks: list[bytes]) -> None:
        self.blocks = blocks
        self.calls = 0

    def read(self, headers):
        return b"".join(self.blocks)

    def read_blocks(self, headers):
        self.calls += 1
        return list(self.blocks)


def _walk(session: Session, first: bytes, limit: int = 40) -> list[bytes]:
    fragments = [first]
    while not fragments[-1][0] & FIN_MASK and len(fragments) < limit:
        nxt = session._handle_fragment(
            bytes([0xC0 | (fragments[-1][0] & 0x0F), FunctionCode.CONFIRM])
        )
        if not nxt:
            break
        fragments.append(nxt)
    return fragments


def _body(fragments: list[bytes]) -> bytes:
    return b"".join(fragment[4:] for fragment in fragments)


#: Six blocks of 500 octets: 3,030 in total, which no single 2,048-octet
#: fragment can carry and which D31 would therefore refuse outright.
WIDE = [_block(i, 500) for i in range(6)]


class TestAProviderThatAnswersInOctets:
    """Unchanged in every respect, which is the point of D35 being a second
    method rather than a change to the first."""

    def test_a_body_that_fits_is_answered_in_one_fragment(self):
        session = Session(Octets([_block(0, 100)]), max_response=2048)

        response = session._handle_fragment(CLASS_0)

        assert response[0] & FIN_MASK
        assert response[4:] == _block(0, 100)

    def test_a_body_too_large_for_a_fragment_is_still_refused(self):
        session = Session(Octets(WIDE), max_response=2048)

        response = session._handle_fragment(CLASS_0)

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert response[4:] == b""


class TestAProviderThatAnswersInBlocks:
    def test_the_same_data_is_delivered_across_fragments(self):
        session = Session(Blocks(WIDE), max_response=2048)

        fragments = _walk(session, session._handle_fragment(CLASS_0))

        assert len(fragments) > 1, "it did not fit one fragment"
        assert fragments[-1][0] & FIN_MASK
        assert _body(fragments) == b"".join(WIDE)

    def test_no_block_is_divided(self):
        """The split points are the provider's. This library never introduces
        one, so every fragment is a whole number of blocks."""
        session = Session(Blocks(WIDE), max_response=2048)

        for fragment in _walk(session, session._handle_fragment(CLASS_0)):
            body, offset = fragment[4:], 0
            while offset < len(body):
                index = body[offset + 3]
                offset += len(WIDE[index])
            assert offset == len(body), "a fragment ended mid-block"

    def test_the_order_is_the_providers(self):
        session = Session(Blocks(WIDE), max_response=2048)

        fragments = _walk(session, session._handle_fragment(CLASS_0))

        assert _body(fragments) == b"".join(WIDE), "blocks were reordered"

    def test_a_smaller_later_block_does_not_jump_the_queue(self):
        """Two large blocks then a small one, sized so the small one would fit
        the gap the second leaves. Filling it would reorder the response, and a
        master applies a fragment in order -- the provider's order is the
        answer, not a packing problem to solve."""
        uneven = [_block(0, 1000), _block(1, 1000), _block(2, 100)]
        session = Session(Blocks(uneven), max_response=2048)

        fragments = _walk(session, session._handle_fragment(CLASS_0))

        assert fragments[0][4:] == uneven[0] + uneven[1], "the first two, and not the third"
        assert _body(fragments) == b"".join(uneven)

    def test_a_single_block_too_large_for_a_fragment_is_refused(self):
        """D35 moves the boundary from the body to one block of it rather than
        removing it: this library still divides nothing."""
        session = Session(Blocks([_block(0, 100), _block(1, 4000)]), max_response=2048)

        response = session._handle_fragment(CLASS_0)

        assert response[3] & IIN2Bit.PARAM_ERROR
        assert response[4:] == b""

    def test_it_is_asked_once_per_response(self):
        provider = Blocks(WIDE)
        session = Session(provider, max_response=2048)

        _walk(session, session._handle_fragment(CLASS_0))

        assert provider.calls == 1

    @pytest.mark.parametrize("ceiling", [512, 1024, 2048, 8192])
    def test_whatever_the_master_can_receive(self, ceiling):
        session = Session(Blocks(WIDE), max_response=ceiling)

        fragments = _walk(session, session._handle_fragment(CLASS_0))

        assert _body(fragments) == b"".join(WIDE)
        for fragment in fragments:
            assert len(fragment) <= ceiling


class TestBothProvidersAgreeWhereTheyCan:
    """The two paths must answer identically whenever the octet provider can
    answer at all, or `read_blocks` is a second implementation rather than a
    second way of reaching the first."""

    @pytest.mark.parametrize("blocks", [[_block(0, 100)], [_block(0, 100), _block(1, 200)]])
    def test_a_body_that_fits_one_fragment(self, blocks):
        octets = Session(Octets(blocks), max_response=2048)
        split = Session(Blocks(blocks), max_response=2048)

        assert octets._handle_fragment(CLASS_0) == split._handle_fragment(CLASS_0)


class TestBlocksBesideEvents:
    @staticmethod
    def _events(count: int = 400) -> EventBuffers:
        buffers = EventBuffers(capacity=max(count, 1))
        for index in range(count):
            buffers.record_analog(
                index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
            )
        return buffers

    def test_the_events_still_lead(self):
        """D20 is unchanged by D35: a static value written after the events
        that led to it leaves the point where it should end up."""
        session = Session(Blocks(WIDE), events=self._events(), max_response=2048)

        fragments = _walk(session, session._handle_fragment(INTEGRITY))

        assert fragments[0][4] == 32, "an event block opens the response"
        assert _body(fragments).endswith(b"".join(WIDE))

    def test_all_of_it_arrives(self):
        session = Session(Blocks(WIDE), events=self._events(), max_response=2048)

        fragments = _walk(session, session._handle_fragment(INTEGRITY))

        assert fragments[-1][0] & FIN_MASK
        assert b"".join(WIDE) in _body(fragments)

    def test_an_integrity_poll_the_octet_provider_would_refuse(self):
        """The case D35 exists for. The same request, the same objects, and the
        difference between an answer and a refusal."""
        refused = Session(Octets(WIDE), events=self._events(), max_response=2048)
        answered = Session(Blocks(WIDE), events=self._events(), max_response=2048)

        assert refused._handle_fragment(INTEGRITY)[3] & IIN2Bit.PARAM_ERROR
        assert not answered._handle_fragment(INTEGRITY)[3] & IIN2Bit.PARAM_ERROR
