"""The fragmentation state machine, driven across its grid rather than at points.

Four defects in this exchange were found one at a time, each in a branch nobody
had written a case for, and each was the same condition closed where it was
found rather than everywhere it held: the bound bypassed two different ways, a
lost final fragment that could not be replayed, and a final fragment carrying
only the provider's body that was neither confirmed nor cached.

So this asserts the properties that must hold on *every* path instead of
enumerating the paths, and walks a grid of buffer sizes, ceilings, body sizes,
count qualifiers and recording rates through them.

A fifth defect then arrived that this file could not have caught, because it
drove conversations with confirmations and nothing else: a function asking for
no response, arriving mid-conversation, left the rest of an abandoned read to be
drawn out by the next confirmation. Interleaving is a dimension now.
"""

from __future__ import annotations

import itertools
import logging

import pytest

from py1815.application import FunctionCode, QualifierCode
from py1815.control import CommandStatus
from py1815.events import EventBuffers, EventClass
from py1815.objects import AnalogPoint
from py1815.session import Session

FIR_MASK, FIN_MASK, CON_MASK = 0x80, 0x40, 0x20
SEQUENCE_SPACE = 16

#: The groups an event block can carry. Anything else is the provider's body.
EVENT_GROUPS = (2, 32)

#: D32's bound, plus the one fragment the body may take beyond it.
MOST_FRAGMENTS = 17


class Provider:
    def __init__(self, octets: int) -> None:
        self.body = bytes([30, 1, 0, 0, 0, 1]) + bytes(octets) if octets else b""
        self.calls = 0

    def read(self, headers):
        self.calls += 1
        return self.body


def _events_in(fragment: bytes) -> int:
    total, body = 0, fragment[4:]
    while len(body) >= 4 and body[0] in EVENT_GROUPS:
        wide = body[2] == QualifierCode.UINT16_COUNT_UINT16_INDEX
        count = int.from_bytes(body[3:5], "little") if wide else body[3]
        header, item = (5, 13) if wide else (4, 12)
        total += count
        body = body[header + count * item :]
    return total


def _request(count: int | None, static: bool, sequence: int = 0) -> bytes:
    head = bytes([0xC0 | sequence, FunctionCode.READ])
    if count is None:
        head += bytes([60, 2, QualifierCode.ALL_OBJECTS])
    else:
        head += bytes([60, 2, QualifierCode.UINT16_COUNT]) + count.to_bytes(2, "little")
    if static:
        head += bytes([60, 1, QualifierCode.ALL_OBJECTS])
    return head


GRID = list(
    itertools.product(
        [0, 5, 170, 1000],  # events already buffered
        [0, 100, 1500],  # octets of static data
        [64, 512, 2048],  # what the master can receive
        [None, 50, 3000],  # the count qualifier, if any
        [0, 100],  # events the device records per confirmation
        # Where the response starts in the sequence space. Fifteen makes every
        # conversation of more than one fragment wrap, which the bound of
        # sixteen means a response beginning at zero never does.
        [0, 15],
    )
)

#: Requests a master might send in the middle of a conversation, each of which
#: must end it (D30). The first two answer nothing at all, which is what made
#: them the easy ones to leave out of a rule about responses.
INTERRUPTIONS = {
    "direct operate, no acknowledgment": bytes(
        [0xC5, FunctionCode.DIRECT_OPERATE_NR, 12, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 1, 0]
    )
    + bytes.fromhex("030164000000c800000000"),
    "immediate freeze, no acknowledgment": bytes([0xC5, FunctionCode.IMMED_FREEZE_NR]),
    "a read": bytes([0xC5, FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS]),
    "an unsupported function": bytes([0xC5, FunctionCode.COLD_RESTART]),
    # Group 80 variation 1 index 7 and its value, which is the write this
    # outstation honours. Without the trailing octet the object has no value,
    # `parse_request` leaves the body empty, and the case passes on the
    # strength of `_is_restart_write` not looking at it -- exercising a
    # malformed write rather than the ordinary one this row is here for.
    "a write": bytes([0xC5, FunctionCode.WRITE, 80, 1, QualifierCode.UINT8_START_STOP, 7, 7, 0x00]),
    "disable unsolicited": bytes([0xC5, FunctionCode.DISABLE_UNSOLICITED]),
}


class _Commands:
    def select(self, controls):
        return [CommandStatus.SUCCESS] * len(controls)

    def operate(self, controls):
        return [CommandStatus.SUCCESS] * len(controls)


@pytest.mark.parametrize("interruption", INTERRUPTIONS.values(), ids=list(INTERRUPTIONS))
@pytest.mark.parametrize("static", [0, 100, 1500])
def test_a_request_mid_conversation_ends_it(interruption, static, caplog):
    """D30, over every shape of request rather than the one a test picked.

    A conversation the master has walked away from must not be continuable, and
    none of its unsent events may be retired by a confirmation that arrives
    after it -- whether the interrupting request was answered or not.
    """
    caplog.set_level(logging.CRITICAL, logger="py1815.session")
    buffers = EventBuffers(capacity=2000)
    for index in range(1000):
        buffers.record_analog(
            index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
        )
    session = Session(
        Provider(static), control_provider=_Commands(), events=buffers, max_response=2048
    )

    first = session._handle_fragment(_request(None, bool(static)))
    assert not first[0] & FIN_MASK, "the fixture must leave a conversation open"
    held = buffers.count(EventClass.CLASS_1)

    session._handle_fragment(interruption)

    assert session._conversation is None, "the conversation outlived the request"
    assert (
        session._handle_fragment(bytes([0xC0 | (first[0] & 0x0F), FunctionCode.CONFIRM])) == b""
    ), "an abandoned conversation was continued"
    assert buffers.count(EventClass.CLASS_1) == held, "events were retired after the abandonment"


@pytest.mark.parametrize(("held", "static", "ceiling", "count", "produce", "start"), GRID)
def test_the_invariants_hold(held, static, ceiling, count, produce, start, caplog):
    caplog.set_level(logging.CRITICAL, logger="py1815.session")
    buffers = EventBuffers(capacity=max(held, 1) + 20_000)
    index = 0
    for index in range(held):
        buffers.record_analog(
            index, AnalogPoint(float(index)), event_class=EventClass.CLASS_1, timestamp_ms=1
        )
    provider = Provider(static)
    session = Session(provider, events=buffers, max_response=ceiling)

    def record(count_: int) -> None:
        nonlocal index
        for _ in range(count_):
            index += 1
            buffers.record_analog(
                index % 250,
                AnalogPoint(float(index)),
                event_class=EventClass.CLASS_1,
                timestamp_ms=1,
            )

    fragments = [session._handle_fragment(_request(count, bool(static), start))]
    while not fragments[-1][0] & FIN_MASK and len(fragments) <= MOST_FRAGMENTS:
        previous = fragments[-1][0] & 0x0F
        assert fragments[-1][0] & CON_MASK, "an unfinished fragment must ask to be confirmed"
        record(produce)

        nxt = session._handle_fragment(bytes([0xC0 | previous, FunctionCode.CONFIRM]))
        assert nxt, "confirming an unfinished fragment must produce the next one"

        # D34, at every step rather than at the one a test happened to pick.
        again = session._handle_fragment(bytes([0xC0 | previous, FunctionCode.CONFIRM]))
        assert again == nxt, "repeating that confirmation must replay it"
        fragments.append(nxt)

    assert fragments[-1][0] & FIN_MASK, f"never ended after {len(fragments)} fragments"
    assert len(fragments) <= MOST_FRAGMENTS

    # The end of the exchange, which is where the walk above stops looking and
    # where two of the four defects lived. A last fragment carrying nothing but
    # the provider's body neither asked to be confirmed nor was kept, so losing
    # it stranded the master exactly as losing any other would.
    if len(fragments) > 1:
        assert fragments[-1][0] & CON_MASK, "the last fragment must ask to be confirmed"
        before = fragments[-2][0] & 0x0F
        assert (
            session._handle_fragment(bytes([0xC0 | before, FunctionCode.CONFIRM]))
            == (fragments[-1])
        ), "and must be replayed if the master repeats the confirmation before it"

    assert (
        session._handle_fragment(bytes([0xC0 | (fragments[-1][0] & 0x0F), FunctionCode.CONFIRM]))
        == b""
    ), "confirming the last fragment ends the exchange"
    assert session._conversation is None

    for number, fragment in enumerate(fragments, 1):
        assert len(fragment) <= ceiling, f"fragment {number} overruns the ceiling"

    assert fragments[0][0] & FIR_MASK
    assert not any(f[0] & FIR_MASK for f in fragments[1:]), "a continuation must not set FIR"
    assert [f[0] & 0x0F for f in fragments] == [
        (start + n) % SEQUENCE_SPACE for n in range(len(fragments))
    ]

    refused = len(fragments) == 1 and fragments[0][4:] == b"" and fragments[0][3] & 0x04
    if static and not refused:
        carrying = [n for n, f in enumerate(fragments, 1) if provider.body in f]
        assert carrying == [len(fragments)], "the body travels in the last fragment and no other"
    assert provider.calls <= 1, "the provider is read once per response"

    if count is not None:
        assert sum(_events_in(f) for f in fragments) <= count
