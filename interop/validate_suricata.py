"""Read a capture of this outstation with Suricata's DNP3 parser.

Suricata's DNP3 support is a large C parser written by the Open Information
Security Foundation from the specification. It reassembles the stream, checks
the link-layer and transport checksums, and raises a named application-layer
event for each thing it finds wrong. That makes it a second independent opinion
on the same octets Wireshark reads, from a codebase with no relationship to
either this library or the other parser.

What this asserts is narrow on purpose: that a parser nobody here wrote can
read every exchange the sweep produced, that it objects to none of the framing,
and that it saw the function codes the sweep sent. It is not a correctness
oracle for the responses -- the master-driven jobs are that.

Exits non-zero, loudly, on anything it cannot verify.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
from typing import NoReturn

#: Application-layer events that mean the traffic was malformed. Suricata names
#: each one, and a checksum it rejected is the assertion this job exists for: a
#: library that computes its own CRC the same wrong way on both sides of a round
#: trip agrees with itself forever and is caught here the first time.
FRAMING_EVENTS = {
    "BAD_LINK_CRC",
    "BAD_TRANSPORT_CRC",
    "LEN_TOO_SMALL",
    "MALFORMED",
    "FLOODED",
}

#: Events that are Suricata declining to decode an object type rather than
#: objecting to the traffic carrying it.
#:
#: The sweep deliberately asks for objects no outstation in the wild serves --
#: a file-transfer group, an analog output block -- in order to reach the
#: unknown-object path. Suricata does not decode those object types either, and
#: says so. That is a statement about its object table, not about our framing,
#: and failing on it would mean the sweep could never test a refusal.
DECODE_ONLY_EVENTS = {"UNKNOWN_OBJECT"}

#: How many of those the sweep is expected to provoke. Naming the event without
#: bounding it would let a genuinely undecodable object appearing somewhere new
#: pass unnoticed, which is the failure the checksum-verdict count guards
#: against at the other end of this file. The sweep asks for three objects this
#: parser does not decode: a file-transfer read, an analog-output write, and the
#: internal-indication write that clears the restart bit.
MAX_DECODE_ONLY_EVENTS = 3

#: Function codes that must appear for the capture to be the one this job
#: expects. Not the full set the sweep sends: Suricata logs a record per
#: application fragment it parses, and a bare confirmation is not one, so
#: requiring everything would pin this job to a logging decision upstream.
REQUIRED_FUNCTIONS = {
    1: "read",
    2: "write",
    3: "select",
    4: "operate",
    5: "direct operate",
    6: "direct operate, no acknowledgment",
    13: "cold restart",
    20: "enable unsolicited",
    21: "disable unsolicited",
    129: "response",
}

#: The sweep walks most of the function code space. A capture carrying only a
#: handful would be a capture of something else.
MINIMUM_DISTINCT_FUNCTIONS = 30


def fail(message: str) -> NoReturn:
    print(f"validate-suricata: FAIL {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("eve", help="path to Suricata's eve.json")
    parser.add_argument(
        "--expect",
        help="the sweep's summary, to check this parser saw every reply that was sent",
    )
    args = parser.parse_args()

    path = pathlib.Path(args.eve)
    if not path.is_file():
        fail(f"{path} does not exist; Suricata did not run or wrote nowhere")

    functions: collections.Counter[int] = collections.Counter()
    kinds: collections.Counter[str] = collections.Counter()
    anomalies: collections.Counter[str] = collections.Counter()

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            fail(f"{path}:{number} is not JSON: {exc}")

        kind = event.get("event_type")
        if kind == "anomaly":
            name = event.get("anomaly", {}).get("event", "<unnamed>")
            if event.get("app_proto") == "dnp3" or "DNP3" in name.upper():
                anomalies[name] += 1
            continue
        if kind != "dnp3":
            continue

        record = event.get("dnp3", {})
        kinds[record.get("type", "<untyped>")] += 1
        application = record.get("application") or {}
        if "function_code" in application:
            functions[application["function_code"]] += 1

    if not kinds:
        fail("Suricata recognized no DNP3 in the capture")

    print(f"validate-suricata: records by kind: {dict(sorted(kinds.items()))}")
    print(f"validate-suricata: {len(functions)} distinct application function codes")
    if anomalies:
        print(f"validate-suricata: anomalies: {dict(sorted(anomalies.items()))}")

    framing = {name: count for name, count in anomalies.items() if name in FRAMING_EVENTS}
    if framing:
        fail(f"Suricata rejected the framing of this outstation's traffic: {framing}")

    unexpected = {
        name: count
        for name, count in anomalies.items()
        if name not in FRAMING_EVENTS and name not in DECODE_ONLY_EVENTS
    }
    if unexpected:
        fail(f"Suricata raised application-layer events nobody has accounted for: {unexpected}")

    decode_only = sum(count for name, count in anomalies.items() if name in DECODE_ONLY_EVENTS)
    if decode_only > MAX_DECODE_ONLY_EVENTS:
        fail(
            f"{decode_only} objects this parser could not decode, expected at most "
            f"{MAX_DECODE_ONLY_EVENTS}; the allowlist is meant to cover the objects the "
            "sweep asks for on purpose, not any new one"
        )

    responses = kinds.get("response", 0)
    if responses == 0:
        fail("the capture contains requests but no responses")

    if args.expect:
        expected = json.loads(pathlib.Path(args.expect).read_text(encoding="utf-8"))
        wanted = expected["application_replies"]
        if responses < wanted:
            # A frame this parser will not accept is dropped rather than
            # reported, so a missing record is how a checksum it rejected
            # actually shows up. Counting its own records would not notice.
            fail(
                f"the outstation sent {wanted} application replies and this parser "
                f"produced a record for {responses} of them; {wanted - responses} "
                "were dropped rather than read"
            )

    missing = {code: name for code, name in REQUIRED_FUNCTIONS.items() if code not in functions}
    if missing:
        fail(f"function codes absent from the capture: {sorted(missing.values())}")

    if len(functions) < MINIMUM_DISTINCT_FUNCTIONS:
        fail(
            f"only {len(functions)} distinct function codes in the capture, "
            f"expected at least {MINIMUM_DISTINCT_FUNCTIONS}"
        )

    print(
        f"validate-suricata: OK, {sum(kinds.values())} DNP3 records read by an "
        f"independent parser with no objection to the framing"
    )


if __name__ == "__main__":
    main()
