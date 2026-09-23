"""Read a capture of this outstation with Wireshark's DNP3 dissector.

The masters in the other jobs judge whether this outstation answers correctly.
This judges something narrower and harder to get from a peer: whether the octets
on the wire are well-formed DNP3 by the reckoning of a dissector written from
the specification by people with no connection to this library.

Wireshark checks every checksum DNP3 carries -- the link header's and each data
chunk's -- and exposes the verdict as a field. That is the assertion worth
having here, because a self-consistent implementation computes its own CRC the
same wrong way on both sides of a round trip and never notices. It is also
cheap: no master to drive, no session to keep alive, just a capture and a
parser that was not written here.

Run against the capture the sweep produces, so the frames examined cover every
function code the sweep sends rather than one integrity poll.

Exits non-zero, loudly, on anything it cannot verify.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import shutil
import subprocess
import sys

#: The two checksum status fields, which are the point of the exercise.
#:
#: Note the prefix. Every other field this dissector registers is ``dnp3.``,
#: and these two are ``dnp.`` -- an inconsistency upstream, not a typo here.
#: Getting it wrong does not produce an error: tshark returns an empty column
#: for a field nobody defines, so every checksum assertion below would pass by
#: having nothing to look at. CHECKSUM_FIELDS_SEEN guards against that.
CHECKSUM_FIELDS = [
    "dnp.hdr.CRC.status",
    "dnp.data_chunk.CRC.status",
]

#: The fields this asks tshark for, one row per DNP3 frame.
FIELDS = [
    "frame.number",
    *CHECKSUM_FIELDS,
    "dnp3.ctl.prifunc",
    "dnp3.ctl.secfunc",
    "dnp3.al.func",
    "dnp3.al.iin",
]

#: Wireshark's ``proto_checksum_vals``: 0 bad, 1 good, 2 unverified, 3 not
#: present, 4 illegal. Anything that is not good on a frame that has the field
#: is a frame this library emitted with a checksum the dissector disagrees with.
CHECKSUM_GOOD = "1"

#: Application function codes the capture must contain for the run to be
#: meaningful. A capture with no responses in it would otherwise pass every
#: checksum assertion by containing nothing to check.
REQUIRED_APP_FUNCTIONS = {
    "0": "confirm",
    "1": "read",
    "2": "write",
    "3": "select",
    "4": "operate",
    "5": "direct operate",
    "6": "direct operate, no acknowledgment",
    "129": "response",
}


def fail(message: str) -> None:
    print(f"validate-pcap: FAIL {message}", file=sys.stderr)
    sys.exit(1)


def run_tshark(tshark: str, pcap: str, port: int) -> list[dict[str, str]]:
    """Every DNP3 frame in the capture, as field rows."""
    command = [
        tshark,
        "-r",
        pcap,
        # The capture is on a non-standard port in some runs, and the dissector
        # keys off the standard one. Saying so explicitly means a passing run
        # cannot be one where nothing was recognized as DNP3 at all.
        "-d",
        f"tcp.port=={port},dnp3",
        "-Y",
        "dnp3",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-o",
        "dnp3.check_crc:TRUE",
    ]
    for field in FIELDS:
        command += ["-e", field]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        fail(f"tshark exited {result.returncode}: {result.stderr.strip()}")

    rows = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        values = line.split("\t")
        values += [""] * (len(FIELDS) - len(values))
        rows.append(dict(zip(FIELDS, values, strict=False)))
    return rows


def _statuses(value: str) -> list[str]:
    """One frame may carry several data chunks, so a field may repeat."""
    return [part for part in value.replace(",", " ").split() if part]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument(
        "--expect",
        help="the sweep's summary, to check this dissector saw every reply that was sent",
    )
    args = parser.parse_args()

    tshark = shutil.which(args.tshark)
    if tshark is None:
        fail(f"{args.tshark} is not on PATH")

    rows = run_tshark(tshark, args.pcap, args.port)
    if not rows:
        fail("the capture contains no frames Wireshark recognized as DNP3")

    bad_header = []
    bad_chunk = []
    #: How many checksum verdicts this dissector actually reported. Zero means
    #: the field names above no longer match what it registers, and every
    #: checksum assertion below is being made against empty strings.
    checksums_seen = 0
    app_functions: collections.Counter[str] = collections.Counter()
    link_functions: collections.Counter[str] = collections.Counter()

    for row in rows:
        number = row["frame.number"]
        for status in _statuses(row["dnp.hdr.CRC.status"]):
            checksums_seen += 1
            if status != CHECKSUM_GOOD:
                bad_header.append(number)
        for status in _statuses(row["dnp.data_chunk.CRC.status"]):
            checksums_seen += 1
            if status != CHECKSUM_GOOD:
                bad_chunk.append(number)
        for function in _statuses(row["dnp3.al.func"]):
            app_functions[function] += 1
        for field in ("dnp3.ctl.prifunc", "dnp3.ctl.secfunc"):
            for function in _statuses(row[field]):
                link_functions[f"{field.rsplit('.', 1)[-1]}:{function}"] += 1

    print(f"validate-pcap: {len(rows)} DNP3 frames, parsed by Wireshark's dissector")
    print(f"validate-pcap: link functions seen: {dict(sorted(link_functions.items()))}")
    print(f"validate-pcap: application functions seen: {dict(sorted(app_functions.items()))}")

    if checksums_seen == 0:
        fail(
            "this dissector reported no checksum verdicts at all, so nothing below "
            f"was checked. The fields {CHECKSUM_FIELDS} are no longer what it "
            "registers; run `tshark -G fields | grep CRC.status` to find the new names"
        )
    print(f"validate-pcap: {checksums_seen} checksum verdicts reported")

    if bad_header:
        fail(f"link header checksum rejected on frames {sorted(set(bad_header))}")
    if bad_chunk:
        fail(f"data chunk checksum rejected on frames {sorted(set(bad_chunk))}")

    missing = {
        code: name for code, name in REQUIRED_APP_FUNCTIONS.items() if code not in app_functions
    }
    if missing:
        fail(
            "the capture does not cover every function code the sweep sends, so "
            f"it is not the capture this job expects: missing {sorted(missing.values())}"
        )

    responses = app_functions.get("129", 0)
    if args.expect:
        wanted = json.loads(pathlib.Path(args.expect).read_text(encoding="utf-8"))[
            "application_replies"
        ]
        if responses < wanted:
            # A frame whose checksum this dissector rejects still appears, with
            # the status field set, so the count above is the check for a frame
            # it could not delimit at all.
            fail(
                f"the outstation sent {wanted} application replies and this dissector "
                f"found {responses} of them in the capture"
            )

    print(
        f"validate-pcap: OK, every checksum verified across {len(rows)} frames, "
        f"{responses} of them responses"
    )


if __name__ == "__main__":
    main()
