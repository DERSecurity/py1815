"""Compare a conformance run with the outcome this repository has on record.

`expected.json` says how each procedure of the dnp3c harness ends against the
py1815 outstation: passed, skipped because of a named option, not implemented
by the harness, or failed for a stated reason. A skip is one of two kinds. The
procedure needs a feature the outstation does not have, and the option that
says so is off for a reason the record gives. Or the procedure is for a device
without a feature, and the outstation has it. The documentation is written
from that record. This script holds the record to what a run did, so the two
cannot drift apart: it fails when a procedure ends differently, when one on
record did not run, and when one ran that is not on record.

It reads what the run wrote: the `results.properties` the harness leaves in
each procedure's directory, and `outcomes.json`, where the program that drives
the harness keeps the harness's own words for each skip and failure.

It also checks the record against the two files beside it: the harness version
is the one `pom.xml` pins, and every option that `device.ini` turns off, or
that a procedure is skipped for, has a reason on record.

    python interop/dnp3c/check_outcomes.py              # compare
    python interop/dnp3c/check_outcomes.py --write      # put a run on record
    python interop/dnp3c/check_outcomes.py --markdown   # the record as tables

`--markdown` prints the tables `docs/conformance.md` carries, which a test
holds to the record. It needs no run.

`--write` keeps the reasons already on record. A failure or an option that is
new is written with an empty reason, which the comparison refuses until
someone has found out why and said so.

Copyright 2026 DER Security Corp. Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent

#: What the harness writes in `results.properties`, and what this record calls it.
_RESULTS = {"pass": "passed", "skip": "skipped", "fail": "failed"}

#: How the harness words a skip for an option, and for a procedure it does not implement.
_DISABLED = re.compile(r"^disabled because (?P<option>\S+) != (?P<value>true|false)$")
_INCOMPLETE = "incomplete procedure"

OUTCOMES = ("passed", "skipped", "not implemented", "failed")

#: What each section of the harness covers, in this project's words. The
#: numbers are the harness's own.
SECTIONS = {
    "6.1": "Link reset and confirmation",
    "6.3": "Link status request",
    "6.4": "Link retries",
    "6.5": "Direction and frame count bits",
    "6.6": "Invalid link frames",
    "6.7": "Self-address",
    "7.2": "Transport segmentation",
    "8.1": "Binary output status",
    "8.2": "Binary output controls",
    "8.3": "Analog output status",
    "8.4": "Analog output controls",
    "8.5": "Class data",
    "8.6": "Internal indications",
    "8.7": "Time",
    "8.8": "Cold restart",
    "8.9": "Fragmentation",
    "8.10": "Multi-drop",
    "8.11": "Unsolicited responses",
    "8.12": "Collision avoidance",
    "8.13": "Binary inputs",
    "8.14": "Binary input events",
    "8.15": "Common time of occurrence",
    "8.16": "Counters and frozen counters",
    "8.17": "Counter events",
    "8.18": "Analog inputs",
    "8.19": "Analog input events",
    "8.20": "Several object headers in one read",
    "8.21": "Double-bit inputs",
    "8.22": "Double-bit input events",
    "8.23": "Device attributes",
}


def _key(procedure: str) -> list[int]:
    """Sort procedure numbers as numbers, so 8.2 comes before 8.10."""
    return [int(part) for part in procedure.split(".")]


def read_properties(path: pathlib.Path) -> dict[str, str]:
    """Read the keys and values of a Java properties file that holds no escapes."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        name, _, value = line.partition("=")
        values[name.strip()] = value.strip()
    return values


def read_run(results: pathlib.Path) -> dict[str, dict[str, str]]:
    """Read how each procedure of a run ended, as the record words it.

    The outcome is the harness's own result file. The detail, which names the
    option behind a skip, is from `outcomes.json`. A procedure whose two
    accounts disagree is an error, because one of them is not from this run.
    """
    summary_file = results / "outcomes.json"
    if not summary_file.is_file():
        raise SystemExit(f"{summary_file} is missing: the run did not finish")
    summary = json.loads(summary_file.read_text(encoding="utf-8"))["procedures"]

    run: dict[str, dict[str, str]] = {}
    for directory in sorted(results.iterdir()):
        result_file = directory / "results.properties"
        if not directory.is_dir() or not result_file.is_file():
            continue
        result = read_properties(result_file).get("result", "")
        if result not in _RESULTS:
            raise SystemExit(f"{result_file} holds result={result!r}, which is not a result")
        entry = {"outcome": _RESULTS[result], "detail": ""}
        told = summary.get(directory.name)
        if told is None:
            raise SystemExit(f"{directory.name} has a result file and is not in {summary_file}")
        if told["outcome"] != entry["outcome"]:
            raise SystemExit(
                f"{directory.name} is {entry['outcome']} in its result file and "
                f"{told['outcome']} in {summary_file}"
            )
        entry["detail"] = told["detail"]
        disabled = _DISABLED.match(entry["detail"])
        if entry["outcome"] == "skipped" and entry["detail"].startswith(_INCOMPLETE):
            entry["outcome"] = "not implemented"
        elif entry["outcome"] == "skipped" and disabled:
            entry["option"] = disabled["option"]
            # "X != true" is a procedure that needs X; "X != false" is one for a device without X.
            entry["needs"] = disabled["value"]
        elif entry["outcome"] == "skipped":
            raise SystemExit(f"{directory.name} was skipped for no option: {entry['detail']!r}")
        run[directory.name] = entry

    without_result = sorted(set(summary) - set(run), key=_key)
    if without_result:
        raise SystemExit(
            "the harness could not run, and so left no result for: " + ", ".join(without_result)
        )
    return dict(sorted(run.items(), key=lambda item: _key(item[0])))


def pinned_version(pom: pathlib.Path) -> str:
    """Return the harness version the Maven project pins."""
    match = re.search(r"<dnp3c\.version>([^<]+)</dnp3c\.version>", pom.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"{pom} does not pin dnp3c.version")
    return match.group(1).strip()


def options_off(device: pathlib.Path) -> list[str]:
    """Return the `supports.*` options a configuration file turns off."""
    return sorted(
        name
        for name, value in read_properties(device).items()
        if name.startswith("supports.") and value == "false"
    )


def compare(
    expected: dict[str, Any], run: dict[str, dict[str, str]], *, version: str, off: list[str]
) -> list[str]:
    """Return every way a run and the files beside the record differ from the record."""
    problems: list[str] = []
    if expected.get("version") != version:
        problems.append(
            f"the record is of dnp3c {expected.get('version')} and pom.xml pins {version}"
        )

    reasons: dict[str, str] = expected.get("options", {})
    procedures: dict[str, dict[str, str]] = expected.get("procedures", {})

    needed = {
        entry["option"]
        for entry in procedures.values()
        if entry.get("outcome") == "skipped" and entry.get("needs") == "true"
    }
    for name in sorted(set(off) | needed):
        if not reasons.get(name, "").strip():
            problems.append(f"{name} is off and the record gives no reason")
    for name in sorted(set(reasons) - set(off) - needed):
        problems.append(
            f"the record gives a reason for {name}, which device.ini does not turn off and no "
            "procedure is skipped for"
        )

    for procedure in sorted(set(procedures) - set(run), key=_key):
        problems.append(
            f"{procedure} is on record as {procedures[procedure]['outcome']} and did not run"
        )
    for procedure in sorted(set(run) - set(procedures), key=_key):
        problems.append(
            f"{procedure} ran, ending {run[procedure]['outcome']}, and is not on record"
        )

    for procedure in sorted(set(procedures) & set(run), key=_key):
        was, now = procedures[procedure], run[procedure]
        if was["outcome"] not in OUTCOMES:
            problems.append(f"{procedure} is on record as {was['outcome']!r}, which is no outcome")
        elif was["outcome"] != now["outcome"]:
            detail = f" ({now['detail']})" if now["detail"] else ""
            problems.append(
                f"{procedure} is on record as {was['outcome']} and ended {now['outcome']}{detail}"
            )
        elif was["outcome"] == "skipped" and (was.get("option"), was.get("needs")) != (
            now.get("option"),
            now.get("needs"),
        ):
            problems.append(
                f"{procedure} is on record as skipped for {was.get('option')} = {was.get('needs')} "
                f"and was skipped for {now.get('option')} = {now.get('needs')}"
            )
        elif was["outcome"] == "failed" and not was.get("reason", "").strip():
            problems.append(f"{procedure} is on record as failed with no reason")
    return problems


def record(
    previous: dict[str, Any], run: dict[str, dict[str, str]], *, version: str, off: list[str]
) -> dict[str, Any]:
    """Build the record of a run, keeping the reasons the previous record gave."""
    old_reasons: dict[str, str] = previous.get("options", {})
    old_procedures: dict[str, dict[str, str]] = previous.get("procedures", {})
    procedures: dict[str, dict[str, str]] = {}
    needed = set(off)
    for procedure, entry in run.items():
        kept = {"outcome": entry["outcome"]}
        if entry["outcome"] == "skipped":
            kept["option"], kept["needs"] = entry["option"], entry["needs"]
            if entry["needs"] == "true":
                needed.add(entry["option"])
        if entry["outcome"] == "failed":
            kept["reason"] = old_procedures.get(procedure, {}).get("reason", "")
        procedures[procedure] = kept
    return {
        "tool": "dnp3c",
        "version": version,
        "options": {name: old_reasons.get(name, "") for name in sorted(needed)},
        "procedures": procedures,
    }


def _listed(procedures: list[str]) -> str:
    """Write procedure numbers as a list, with a run of three or more as "first to last"."""
    runs: list[list[str]] = []
    for procedure in sorted(procedures, key=_key):
        last = runs[-1][-1] if runs else None
        if last is not None and [*_key(last)[:-1], _key(last)[-1] + 1] == _key(procedure):
            runs[-1].append(procedure)
        else:
            runs.append([procedure])
    return ", ".join(f"{run[0]} to {run[-1]}" if len(run) > 2 else ", ".join(run) for run in runs)


def _table(header: list[str], rows: list[list[str]]) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def markdown(expected: dict[str, Any]) -> dict[str, str]:
    """Return the record as the tables the documentation carries, by name."""
    procedures: dict[str, dict[str, str]] = expected["procedures"]
    reasons: dict[str, str] = expected["options"]

    def having(outcome: str, within: str | None = None) -> list[str]:
        return [
            procedure
            for procedure, entry in procedures.items()
            if entry["outcome"] == outcome
            and (within is None or ".".join(procedure.split(".")[:2]) == within)
        ]

    sections = sorted({".".join(p.split(".")[:2]) for p in procedures}, key=_key)
    by_section = _table(
        ["Section", "Covers", "Passed", "Skipped", "Failed", "Not implemented by dnp3c"],
        [
            [section, SECTIONS[section], *(_listed(having(o, section)) for o in _COLUMNS)]
            for section in sections
        ],
    )

    def skipped_for(needs: str) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for procedure, entry in procedures.items():
            if entry["outcome"] == "skipped" and entry["needs"] == needs:
                found.setdefault(entry["option"], []).append(procedure)
        return found

    lacking = skipped_for("true")
    off_table = _table(
        ["Option turned off", "Why", "Procedures skipped for it"],
        [
            [f"`{name}`", reason, _listed(lacking.get(name, [])) or "none"]
            for name, reason in sorted(reasons.items())
        ],
    )
    for_devices_without = _table(
        ["Procedure", "For a device where this is off"],
        [
            [_listed(found), f"`{name}`"]
            for name, found in sorted(skipped_for("false").items(), key=lambda i: _key(i[1][0]))
        ],
    )
    failures: dict[str, list[str]] = {}
    for procedure in having("failed"):
        failures.setdefault(procedures[procedure]["reason"], []).append(procedure)
    failed = _table(
        ["Procedure", "What happens, and which document it turns on"],
        [[_listed(found), reason] for reason, found in failures.items()],
    )
    return {
        "sections": by_section,
        "options": off_table,
        "without": for_devices_without,
        "failed": failed,
        "not-implemented": _listed(having("not implemented")),
    }


#: The outcome each column of the table of sections lists, in order.
_COLUMNS = ("passed", "skipped", "failed", "not implemented")


def main(argv: list[str] | None = None) -> int:
    """Compare a run with the record, or put the run on record. Return the exit status."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0])
    parser.add_argument("--results", type=pathlib.Path, default=HERE / "results")
    parser.add_argument("--expected", type=pathlib.Path, default=HERE / "expected.json")
    parser.add_argument("--pom", type=pathlib.Path, default=HERE / "pom.xml")
    parser.add_argument("--device", type=pathlib.Path, default=HERE / "device.ini")
    parser.add_argument(
        "--write", action="store_true", help="put this run on record, keeping the reasons given"
    )
    parser.add_argument(
        "--markdown", action="store_true", help="print the record as tables, without a run"
    )
    args = parser.parse_args(argv)

    if args.markdown:
        tables = markdown(json.loads(args.expected.read_text(encoding="utf-8")))
        for name, table in tables.items():
            print(f"<!-- record: {name} -->\n{table}\n<!-- end -->\n")
        return 0

    run = read_run(args.results)
    version = pinned_version(args.pom)
    off = options_off(args.device)
    previous: dict[str, Any] = (
        json.loads(args.expected.read_text(encoding="utf-8")) if args.expected.is_file() else {}
    )

    if args.write:
        args.expected.write_text(
            json.dumps(record(previous, run, version=version, off=off), indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"wrote {args.expected}")
        previous = json.loads(args.expected.read_text(encoding="utf-8"))

    problems = compare(previous, run, version=version, off=off)
    for problem in problems:
        print(problem)
    if problems:
        print("the run and the record differ; see interop/dnp3c/README.md")
        return 1
    tally: dict[str, int] = {}
    for entry in run.values():
        tally[entry["outcome"]] = tally.get(entry["outcome"], 0) + 1
    print(
        "the run is the one on record: " + ", ".join(f"{n} {o}" for o, n in sorted(tally.items()))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
