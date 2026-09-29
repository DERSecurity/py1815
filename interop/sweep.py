"""Every function code this outstation is expected to answer, driven over a socket.

The unit suite pins each layer in isolation and the master probes read points.
Neither walks the function code space, which is where an outstation's contract
mostly lives: what it answers, what it refuses out loud, and the ones it is
supposed to meet with silence.

This drives all of it over a real connection and checks the reply against a
declared expectation. It is also what the capture-based jobs record: the
independent parsers in ``validate_pcap.py`` and the Suricata job read the
traffic this produces, so a sweep that covers more function codes is also a
capture that covers more of the wire format.

Requests are built with this library, which the peer-driven jobs deliberately
are not. That is the division of labor: this job proves the outstation answers
every function code the way it says it does, and the independent parsers and
masters judge whether the octets it emitted are really DNP3.

Exits non-zero, loudly, on anything that does not match.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import socket
import sys
from dataclasses import dataclass, field

# A sibling script rather than a package module: interop/ holds scripts the
# jobs run directly, so the script's own directory is what puts this on the
# path. tests/test_interop_fixture.py loads outstation.py the same way.
from pcap import Capture

from py1815 import link
from py1815.application import (
    CON_MASK,
    FIN_MASK,
    FIR_MASK,
    SEQUENCE_MODULUS,
    FunctionCode,
    IIN2Bit,
    IINBit,
    QualifierCode,
)
from py1815.transport import segment

#: Long enough that a reply which is coming has arrived on a loopback, short
#: enough that the cases expecting silence do not dominate the runtime.
REPLY_TIMEOUT = 1.0

OUTSTATION = 1024
MASTER = 1

#: A class 0 read: everything static the outstation holds.
CLASS_0 = bytes([FunctionCode.READ, 60, 1, QualifierCode.ALL_OBJECTS])

#: Group 80 variation 1 index 7 -- the internal indication a master writes to
#: clear the restart bit. The one write this outstation honors.
CLEAR_RESTART = bytes([FunctionCode.WRITE, 80, 1, QualifierCode.UINT8_START_STOP, 7, 7, 0x00])

#: The same qualifier against an object nobody serves, which is refused as an
#: unknown object rather than an unsupported function: WRITE itself is
#: supported, and the master should learn which of the two went wrong.
WRITE_UNKNOWN = bytes(
    [FunctionCode.WRITE, 40, 1, QualifierCode.UINT8_START_STOP, 0, 0, 0x00, 0x00, 0x00, 0x00]
)


@dataclass(frozen=True)
class Expect:
    """What a request should produce.

    ``silent`` and the rest are mutually exclusive: a function that asks for no
    response cannot also be checked for indication bits.
    """

    silent: bool = False
    #: Application function code of the reply, for application requests.
    function: int | None = None
    #: Second-octet indication bits that must be set.
    iin2: int = 0
    #: Second-octet indication bits that must be clear.
    iin2_clear: int = 0
    #: Link function of the reply, for link-layer requests that never reach the
    #: application layer.
    link_function: int | None = None
    #: True when the reply must carry object data rather than be a null response.
    objects: bool = False


@dataclass(frozen=True)
class Case:
    name: str
    payload: bytes = b""
    expect: Expect = field(default_factory=Expect)
    #: Link-layer function carrying it. Everything is unconfirmed user data
    #: except the cases that exist to exercise the link layer itself.
    link_function: int = link.PrimaryFunction.UNCONFIRMED_USER_DATA
    note: str = ""
    #: The restart indication expected in this reply, when it differs from the
    #: running state. The write that clears the bit is already cleared in its
    #: own response, which is the one place the two disagree.
    restart: bool | None = None


def _app(function: int, body: bytes = b"", *, sequence: int = 0) -> bytes:
    """An application fragment: control octet, function code, then any body."""
    return bytes([0xC0 | (sequence & 0x0F), function]) + body


def _refused(function: int, name: str, note: str = "") -> Case:
    """A function this outstation answers with FUNC_NOT_SUPPORTED.

    Sent with no object data. A refusal is decided on the function code, so a
    body would only add a parse that the refusal never reaches.
    """
    return Case(
        name=name,
        payload=_app(function),
        expect=Expect(function=FunctionCode.RESPONSE, iin2=IIN2Bit.FUNC_NOT_SUPPORTED),
        note=note,
    )


def _silent(function: int, name: str) -> Case:
    """A function the standard says draws no reply at all.

    IEEE 1815-2012 Table 4-2 describes each of these as "same as function code N
    but outstation shall not send a response", so the expectation is silence
    whether or not this outstation implements what was asked.
    """
    return Case(
        name=name,
        payload=_app(function),
        expect=Expect(silent=True),
        note="the standard says this one draws no reply",
    )


def _control_without_objects(function: int, name: str) -> Case:
    """A control function carrying no objects at all.

    Malformed rather than unimplemented. The function is supported and the
    request names nothing to do, so the refusal is PARAM_ERROR against the
    fragment -- there is no object to attach a status to, which is the
    distinction D15 draws.
    """
    return Case(
        name=name,
        payload=_app(function),
        expect=Expect(function=FunctionCode.RESPONSE, iin2=IIN2Bit.PARAM_ERROR),
        note="supported, but nothing was asked for",
    )


def _crob_block(index: int) -> bytes:
    """One LATCH_ON against *index*, as group 12 variation 1."""
    crob = bytes.fromhex("030164000000c800000000")
    header = bytes([12, 1, QualifierCode.UINT8_COUNT_UINT8_INDEX, 1])
    return header + bytes([index]) + crob


#: The functions that must be answered, the ones that must be refused out loud,
#: and the ones that must be met with silence.
#:
#: Ordering matters in one place: clearing the restart indication changes the
#: first indication octet for every response after it, so the cases that assert
#: the restart bit run before it and the case that asserts it is gone runs after.
CASES: list[Case] = [
    # -- the link layer, which the application layer never sees ---------------
    Case(
        name="link: reset link states",
        link_function=link.PrimaryFunction.RESET_LINK_STATES,
        expect=Expect(link_function=link.SecondaryFunction.ACK),
    ),
    Case(
        name="link: test link states",
        link_function=link.PrimaryFunction.TEST_LINK_STATES,
        expect=Expect(link_function=link.SecondaryFunction.ACK),
    ),
    Case(
        name="link: request link status",
        link_function=link.PrimaryFunction.REQUEST_LINK_STATUS,
        expect=Expect(link_function=link.SecondaryFunction.LINK_STATUS),
    ),
    # -- reads ----------------------------------------------------------------
    Case(
        name="read: class 0",
        payload=_app(FunctionCode.READ, CLASS_0[1:]),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
    ),
    Case(
        name="read: analog inputs g30v1 over a range",
        payload=_app(FunctionCode.READ, bytes([30, 1, QualifierCode.UINT8_START_STOP, 0, 4])),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
    ),
    Case(
        name="read: an object nobody serves",
        payload=_app(FunctionCode.READ, bytes([70, 1, QualifierCode.UINT8_START_STOP, 0, 0])),
        expect=Expect(function=FunctionCode.RESPONSE, iin2=IIN2Bit.OBJECT_UNKNOWN),
        note="refused as an unknown object, not an unsupported function",
    ),
    # -- controls ------------------------------------------------------------
    #
    # These answered FUNC_NOT_SUPPORTED until the fixture gained a control
    # provider. They now reach the body parser, and a control function carrying
    # no objects is a malformed request rather than an unimplemented one.
    _control_without_objects(FunctionCode.SELECT, "control: select, no objects"),
    _control_without_objects(FunctionCode.OPERATE, "control: operate, no objects"),
    _control_without_objects(FunctionCode.DIRECT_OPERATE, "control: direct operate, no objects"),
    Case(
        name="control: direct operate, a point the fixture owns",
        payload=_app(FunctionCode.DIRECT_OPERATE, _crob_block(0)),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
        note="answered per object, so the reply carries the control back",
    ),
    Case(
        name="control: direct operate, a point it does not",
        payload=_app(FunctionCode.DIRECT_OPERATE, _crob_block(9)),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
        note="refused per object rather than per fragment: the IIN stays clear",
    ),
    _silent(FunctionCode.DIRECT_OPERATE_NR, "control: direct operate, no acknowledgment"),
    # -- the event classes ----------------------------------------------------
    *(
        Case(
            name=f"read: class {number}",
            payload=_app(FunctionCode.READ, bytes([60, number + 1, 0x06])),
            expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
            note="answered from the buffers rather than from the point map",
        )
        for number in (1, 2, 3)
    ),
    Case(
        name="read: integrity poll",
        # Classes 1, 2, 3 and then 0, which is what a real master sends on
        # startup and the one request that exercises both sources at once.
        payload=_app(
            FunctionCode.READ,
            bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06, 60, 1, 0x06]),
        ),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
        note="events and static data in one response, the events in front",
    ),
    # -- the one unsolicited request this outstation can honestly agree to ----
    Case(
        name="unsolicited: disable",
        # Naming classes 1, 2 and 3, which is the shape a real master sends
        # rather than a bare function code.
        payload=_app(
            FunctionCode.DISABLE_UNSOLICITED,
            bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06]),
        ),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=IIN2Bit.FUNC_NOT_SUPPORTED),
        note="an outstation that sends none is already in the state this asks for (D21)",
    ),
    # -- everything else the outstation does not implement --------------------
    _refused(FunctionCode.IMMED_FREEZE, "freeze: immediate"),
    _refused(FunctionCode.FREEZE_CLEAR, "freeze: clear"),
    _refused(FunctionCode.FREEZE_AT_TIME, "freeze: at time"),
    _refused(FunctionCode.COLD_RESTART, "restart: cold"),
    _refused(FunctionCode.WARM_RESTART, "restart: warm"),
    _refused(FunctionCode.INITIALIZE_DATA, "application: initialize data"),
    _refused(FunctionCode.INITIALIZE_APPLICATION, "application: initialize"),
    _refused(FunctionCode.START_APPLICATION, "application: start"),
    _refused(FunctionCode.STOP_APPLICATION, "application: stop"),
    _refused(FunctionCode.SAVE_CONFIGURATION, "configuration: save"),
    _refused(
        FunctionCode.ENABLE_UNSOLICITED,
        "unsolicited: enable",
        "asks for something this outstation does not do; refused rather than agreed to",
    ),
    _refused(FunctionCode.ASSIGN_CLASS, "class: assign"),
    _refused(FunctionCode.DELAY_MEASURE, "time: delay measurement"),
    _refused(FunctionCode.RECORD_CURRENT_TIME, "time: record current"),
    _refused(FunctionCode.OPEN_FILE, "file: open"),
    _refused(FunctionCode.CLOSE_FILE, "file: close"),
    _refused(FunctionCode.DELETE_FILE, "file: delete"),
    _refused(FunctionCode.GET_FILE_INFO, "file: get info"),
    _refused(FunctionCode.AUTHENTICATE_FILE, "file: authenticate"),
    _refused(FunctionCode.ABORT_FILE, "file: abort"),
    _refused(FunctionCode.AUTH_REQUEST, "secure authentication: request"),
    _refused(0x7F, "a function code the standard does not define"),
    # -- the rest of the no-response family -----------------------------------
    #
    # IEEE 1815-2012 Table 4-2 describes each of these as "same as function code
    # N but outstation shall not send a response". The obligation is on the
    # function code, not on whether the outstation implements what was asked, so
    # a refusal here would be a fragment sent to a master that is not listening.
    _silent(FunctionCode.IMMED_FREEZE_NR, "freeze: immediate, no acknowledgment"),
    _silent(FunctionCode.FREEZE_CLEAR_NR, "freeze: clear, no acknowledgment"),
    _silent(FunctionCode.FREEZE_AT_TIME_NR, "freeze: at time, no acknowledgment"),
    _silent(
        FunctionCode.AUTH_REQUEST_NO_ACK,
        "secure authentication: request, no acknowledgment",
    ),
    # -- confirmations are not requests ---------------------------------------
    Case(
        name="confirm",
        payload=_app(FunctionCode.CONFIRM),
        expect=Expect(silent=True),
        note="a confirmation is not a request; answering one would be unasked for",
    ),
    # -- writes, last, because the first one changes every later response -----
    Case(
        name="write: an object this outstation does not hold",
        payload=_app(FunctionCode.WRITE, WRITE_UNKNOWN[1:]),
        expect=Expect(function=FunctionCode.RESPONSE, iin2=IIN2Bit.OBJECT_UNKNOWN),
    ),
    Case(
        name="write: clear the restart indication",
        payload=_app(FunctionCode.WRITE, CLEAR_RESTART[1:]),
        expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF),
        restart=False,
        note="the clearing write is itself answered with the bit already clear",
    ),
]

#: Run after the sweep, to show the write above actually took effect rather
#: than merely being answered.
AFTER_RESTART_CLEARED = Case(
    name="read: class 0, with the restart indication cleared",
    payload=_app(FunctionCode.READ, CLASS_0[1:]),
    expect=Expect(function=FunctionCode.RESPONSE, iin2_clear=0xFF, objects=True),
)


class Failure(Exception):
    """A case whose reply did not match its expectation."""


@dataclass(frozen=True)
class Conversation:
    """A request whose answer the master has to walk rather than just read.

    A response that sets `CON` is only half an exchange: the master confirms it,
    and an outstation with more to send answers that confirmation with the next
    fragment. Every other case in this file is one request and one reply, so
    none of them reaches that path -- the nearest, "confirm", sends a bare
    confirmation with nothing outstanding to confirm.
    """

    name: str
    payload: bytes
    #: True when the answer must take more than one fragment.
    multi: bool = False
    #: True when the first fragment must carry object data.
    objects: bool = False
    #: Where a walk stops and calls the exchange a runaway. Sixteen fragments of
    #: events and one for static data is the outstation's own bound.
    limit: int = 18
    note: str = ""


#: Conversations, walked after the single-reply sweep so the capture holds both.
#: The outstation seeds events at startup, and confirming retires them, so these
#: assert the shape of the exchange rather than how much it carried.
CONVERSATIONS = [
    Conversation(
        name="conversation: class 1",
        payload=_app(FunctionCode.READ, bytes([60, 2, 0x06])),
        objects=True,
        note="events, confirmed, and the confirmation drawing no further traffic",
    ),
    Conversation(
        name="conversation: integrity poll",
        payload=_app(
            FunctionCode.READ, bytes([60, 2, 0x06, 60, 3, 0x06, 60, 4, 0x06, 60, 1, 0x06])
        ),
        objects=True,
        note="what a real master sends on startup",
    ),
]


def _fragment_of(reply: bytes) -> bytes:
    """The application fragment inside a reply, or a failure saying why not."""
    frames = link.FrameReader().feed(reply)
    if not frames:
        raise Failure(f"reply is not a complete link frame: {reply.hex()}")
    fragment = frames[-1].payload[1:]
    if len(fragment) < 4:
        raise Failure(f"application fragment is too short: {fragment.hex()}")
    return fragment


def _walk(sock: socket.socket, capture, conversation: Conversation) -> str:
    """Send a request and confirm each fragment until the outstation is done.

    Checks the things only a walk can see: that `FIR` opens the exchange and
    nothing else sets it, that `FIN` closes it, that the sequence advances by
    one each time around the sequence space, and that a fragment asking to be
    confirmed is answered when it is.
    """
    request = _frame_bytes(conversation.payload)
    sock.sendall(request)
    if capture:
        capture.sent(request)
    reply = _read_reply(sock)
    if capture:
        capture.received(reply)
    if not reply:
        raise Failure("expected a reply, got silence")

    fragments = [_fragment_of(reply)]
    while fragments[-1][0] & CON_MASK and not fragments[-1][0] & FIN_MASK:
        if len(fragments) >= conversation.limit:
            raise Failure(f"still going after {len(fragments)} fragments")
        confirm = _frame_bytes(_app(FunctionCode.CONFIRM, sequence=fragments[-1][0] & 0x0F))
        sock.sendall(confirm)
        if capture:
            capture.sent(confirm)
        reply = _read_reply(sock)
        if capture:
            capture.received(reply)
        if not reply:
            raise Failure(f"confirming fragment {len(fragments)} drew silence")
        fragments.append(_fragment_of(reply))

    if not fragments[0][0] & FIR_MASK:
        raise Failure("the first fragment does not set FIR")
    for number, fragment in enumerate(fragments[1:], 2):
        if fragment[0] & FIR_MASK:
            raise Failure(f"fragment {number} sets FIR")
    if not fragments[-1][0] & FIN_MASK:
        raise Failure("the exchange ended without FIN")

    first = fragments[0][0] & 0x0F
    expected = [(first + n) % SEQUENCE_MODULUS for n in range(len(fragments))]
    actual = [f[0] & 0x0F for f in fragments]
    if actual != expected:
        raise Failure(f"sequences {actual}, expected {expected}")

    if conversation.multi and len(fragments) < 2:
        raise Failure("expected more than one fragment")
    if conversation.objects and len(fragments[0]) <= 4:
        raise Failure("expected objects, got a null response")

    # The last fragment is confirmed like any other, and draws nothing further:
    # the exchange is over and a confirmation is not a request.
    if fragments[-1][0] & CON_MASK:
        confirm = _frame_bytes(_app(FunctionCode.CONFIRM, sequence=fragments[-1][0] & 0x0F))
        sock.sendall(confirm)
        if capture:
            capture.sent(confirm)
        trailing = _read_reply(sock)
        if capture:
            capture.received(trailing)
        if trailing:
            raise Failure(f"confirming the last fragment drew {len(trailing)} octets")

    plural = "fragment" if len(fragments) == 1 else "fragments"
    return f"{len(fragments)} {plural}, confirmed"


def _frame_bytes(payload: bytes) -> bytes:
    """One link frame carrying an application fragment."""
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    segments = segment(payload)
    if len(segments) != 1:
        raise Failure("request does not fit one transport segment")
    return link.build(control, destination=OUTSTATION, source=MASTER, payload=segments[0])


def _frame(case: Case) -> bytes:
    """One link frame carrying the case.

    An application fragment travels inside a transport segment, so it is run
    through the segmenter rather than written into the frame directly. Every
    request here is small enough to be one segment; using the segmenter anyway
    keeps the transport header honest rather than hard-coding FIR and FIN.
    """
    control = link.control_byte(from_master=True, primary=True, function=case.link_function)
    payload = b""
    if case.payload:
        segments = segment(case.payload)
        if len(segments) != 1:
            raise Failure(f"{case.name} does not fit one transport segment")
        payload = segments[0]
    return link.build(control, destination=OUTSTATION, source=MASTER, payload=payload)


def _read_reply(sock: socket.socket) -> bytes:
    """Whatever arrives within the reply window, which may be nothing."""
    sock.settimeout(REPLY_TIMEOUT)
    chunks = bytearray()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks += chunk
            # A reply is one or two frames and arrives together; a second read
            # is only to catch a link ack followed by a response.
            sock.settimeout(0.15)
    except TimeoutError:
        pass
    except OSError as exc:
        raise Failure(f"socket error while reading the reply: {exc}") from exc
    return bytes(chunks)


def _check(case: Case, reply: bytes, *, restart_expected: bool | None) -> tuple[str, bool | None]:
    """Compare a reply against its expectation.

    Returns what was observed and the restart indication this reply carried, so
    the caller can adopt it as the baseline. ``restart_expected`` of None means
    the baseline is not yet known and the bit is recorded rather than asserted:
    the association keeps its state across connections, so a sweep run twice
    against one outstation meets a restart bit the first run already cleared.
    What matters is that it does not change except where a master clears it.
    """
    if case.expect.silent:
        if reply:
            raise Failure(f"expected silence, got {len(reply)} octets: {reply.hex()}")
        return "silence", None

    if not reply:
        raise Failure("expected a reply, got silence")

    frames = link.FrameReader().feed(reply)
    if not frames:
        raise Failure(f"reply is not a complete link frame: {reply.hex()}")

    if case.expect.link_function is not None:
        frame = frames[0]
        if frame.is_primary:
            raise Failure("expected a secondary link frame, got a primary one")
        if frame.function != case.expect.link_function:
            raise Failure(
                f"expected link function {case.expect.link_function}, got {frame.function}"
            )
        return f"link {link.SecondaryFunction(frame.function).name}", None

    # The application reply is the last frame: a confirmed request is answered
    # with a link acknowledgment first.
    fragment = frames[-1].payload[1:]
    if len(fragment) < 4:
        raise Failure(f"application fragment is too short to be a response: {fragment.hex()}")

    function, iin1, iin2 = fragment[1], fragment[2], fragment[3]
    if case.expect.function is not None and function != case.expect.function:
        raise Failure(f"expected function {case.expect.function:#04x}, got {function:#04x}")

    missing = case.expect.iin2 & ~iin2
    if missing:
        raise Failure(f"expected indication bits {missing:#04x} set, IIN2 was {iin2:#04x}")

    unwanted = case.expect.iin2_clear & ~case.expect.iin2 & iin2
    if unwanted:
        raise Failure(f"expected indication bits {unwanted:#04x} clear, IIN2 was {iin2:#04x}")

    restart = bool(iin1 & IINBit.DEVICE_RESTART)
    if restart_expected is not None and restart is not restart_expected:
        state = "set" if restart_expected else "clear"
        raise Failure(f"expected the restart indication {state}, IIN1 was {iin1:#04x}")

    if case.expect.objects and len(fragment) <= 4:
        raise Failure("expected object data, got a null response")

    described = f"iin {iin1:#04x} {iin2:#04x}" + (
        f", {len(fragment) - 4} octets of objects" if len(fragment) > 4 else ""
    )
    return described, restart


def run(host: str, port: int, pcap: str | None = None, summary: str | None = None) -> int:
    failures: list[tuple[str, str]] = []
    #: What the parser jobs cross-check their own reading against. A parser that
    #: silently dropped a frame it could not accept reports fewer responses than
    #: this outstation is recorded as having sent, which is the signal that a
    #: count of its own records would miss.
    replies_received = 0
    #: Replies carrying an application fragment, which is the subset a parser
    #: that logs application transactions will have a record for. The link-layer
    #: acknowledgments are replies too, and are not.
    application_replies = 0
    capture = Capture(server_port=port) if pcap else None
    #: Learned from the first application reply rather than assumed. See _check.
    restart_expected: bool | None = None

    with socket.create_connection((host, port), timeout=10.0) as sock:
        if capture:
            capture.open()
        for case in CASES:
            request = _frame(case)
            sock.sendall(request)
            if capture:
                capture.sent(request)
            try:
                expected_restart = restart_expected if case.restart is None else case.restart
                reply = _read_reply(sock)
                if reply:
                    replies_received += 1
                    if case.payload:
                        application_replies += 1
                if capture:
                    capture.received(reply)
                observed, restart = _check(case, reply, restart_expected=expected_restart)
                if restart is not None and restart_expected is None:
                    restart_expected = restart
            except Failure as exc:
                failures.append((case.name, str(exc)))
                print(f"sweep: FAIL {case.name}: {exc}", file=sys.stderr)
                continue
            note = f"  ({case.note})" if case.note else ""
            print(f"sweep: ok   {case.name}: {observed}{note}")
            if case.restart is not None:
                # A case that declares the bit also sets the running state, so
                # the clearing write does not need to be recognized by name.
                restart_expected = case.restart

        for conversation in CONVERSATIONS:
            try:
                observed = _walk(sock, capture, conversation)
            except Failure as exc:
                failures.append((conversation.name, str(exc)))
                print(f"sweep: FAIL {conversation.name}: {exc}", file=sys.stderr)
                continue
            note = f"  ({conversation.note})" if conversation.note else ""
            print(f"sweep: ok   {conversation.name}: {observed}{note}")

        final = _frame(AFTER_RESTART_CLEARED)
        sock.sendall(final)
        if capture:
            capture.sent(final)
        try:
            reply = _read_reply(sock)
            if reply:
                replies_received += 1
                application_replies += 1
            if capture:
                capture.received(reply)
            observed, _ = _check(AFTER_RESTART_CLEARED, reply, restart_expected=False)
            print(f"sweep: ok   {AFTER_RESTART_CLEARED.name}: {observed}")
        except Failure as exc:
            failures.append((AFTER_RESTART_CLEARED.name, str(exc)))
            print(f"sweep: FAIL {AFTER_RESTART_CLEARED.name}: {exc}", file=sys.stderr)

    if capture and pcap:
        capture.close()
        print(f"sweep: wrote {capture.write(pcap)} packets to {pcap}")

    if summary:
        pathlib.Path(summary).write_text(
            json.dumps(
                {
                    "replies": replies_received,
                    "application_replies": application_replies,
                },
                indent=1,
            ),
            encoding="utf-8",
        )
        print(
            f"sweep: recorded {replies_received} replies "
            f"({application_replies} carrying an application fragment) in {summary}"
        )

    total = len(CASES) + 1
    if failures:
        print(f"\nsweep: FAILED, {len(failures)} of {total} cases", file=sys.stderr)
        return 1
    print(f"\nsweep: OK, {total} function codes behaved as declared")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument(
        "--pcap",
        help="write the exchange to this capture file, for the parser jobs to read",
    )
    parser.add_argument(
        "--summary",
        help="record what this run observed, for the parser jobs to check against",
    )
    args = parser.parse_args()
    sys.exit(run(args.host, args.port, args.pcap, args.summary))


if __name__ == "__main__":
    main()
