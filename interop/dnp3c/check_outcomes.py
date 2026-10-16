"""Compare a conformance run with the outcome this repository has on record.

`expected.json` says how each procedure of the dnp3c harness ends against the
py1815 outstation, for one revision of the certification procedure and one
subset level: passed, with any warning the harness gave; skipped, with the
harness's reason; excluded or failed, with a reason this project gives; or not
implemented by the harness. The documentation is written from that record.
This script holds the record to what a run did, so the two cannot drift apart:
it fails when a procedure ends differently, when one on record did not run,
when one ran that is not on record, and when a pass gains or loses a warning.

It reads what the run wrote: the `results.properties` the harness leaves in
each procedure's directory, and `outcomes.json`, where the program that drives
the harness keeps the harness's own words for each outcome.

It also checks the record against the two files beside it: the harness version
is the one `pom.xml` pins, the subset level is the one `device.ini` sets, and
every option that `device.ini` turns off and that the record depends on has a
reason on record.

    python interop/dnp3c/check_outcomes.py              # compare
    python interop/dnp3c/check_outcomes.py --write      # put a run on record
    python interop/dnp3c/check_outcomes.py --markdown   # the record as tables

`--markdown` prints the tables `docs/conformance.md` carries, which a test
holds to the record. It needs no run.

`--write` keeps the reasons already on record. A failure, an exclusion or an
option that is new is written with an empty reason, which the comparison
refuses until someone has found out why and said so.

Copyright 2026 DER Security Corp. Licensed under the GNU General Public License,
version 3 only: see LICENSE in this directory.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent

#: The revision of the certification procedure a new record is of.
REVISION = "3.1r1"

#: What the harness writes in `results.properties`, and what this record calls it.
_RESULTS = {"pass": "passed", "skip": "skipped", "fail": "failed", "excluded": "excluded"}

#: How the harness words a skip for the configuration, for another subset level, and for a
#: procedure it does not implement.
_DISABLED = "disabled because "
_NOT_APPLICABLE = "not applicable: "
_INCOMPLETE = "incomplete procedure"

#: An option a skip reason names, with the value it is compared with.
_CONDITION = re.compile(r"(?P<option>[A-Za-z][\w.]*) (?:!=|==) (?:true|false)")

OUTCOMES = ("passed", "skipped", "excluded", "not implemented", "failed")

#: What each section of revision 3.1 rev 1 covers, in the harness's words. A procedure is
#: in the section its first two numbers name, or its first one where there is no such
#: section.
SECTIONS = {
    "6.1": "Reset Link and Passive Confirm support",
    "6.3": "Request Link Status",
    "6.4": "Test Retries",
    "6.5": "DIR and FCV Bits",
    "6.6": "Data Link Rejects Invalid Frames",
    "6.7": "Self-Address Support",
    "7": "Transport Layer",
    "8.1": "Binary Output Status",
    "8.2": "Binary Outputs",
    "8.3": "Analog Output Status",
    "8.4": "Analog Outputs",
    "8.5": "Class Data",
    "8.6": "Indications",
    "8.7": "Time",
    "8.8": "Cold Restart",
    "8.9": "Application Layer Fragmentation",
    "8.10": "Multi-Drop Support",
    "8.11": "Unsolicited Responses",
    "8.12": "Collision Avoidance",
    "8.13": "Binary Inputs Specific Object Requests",
    "8.14": "Binary Input Change Specific Requests",
    "8.15": "Common Time of Occurrence",
    "8.16": "Binary Counters Specific Object Requests",
    "8.17": "Binary Counters, Event",
    "8.18": "Analog Input",
    "8.19": "Analog Change Event",
    "8.20": "Multiple Read Requests",
    "8.21": "Double-bit Inputs",
    "8.22": "Double-bit Input Change",
    "8.23": "Specific Point Ranges",
    "8.24": "Specific variations for Static Inputs",
    "8.25": "Specific Variations for Events",
    "8.26": "Assign Class",
    "9.5": "Network: All Communication Methods",
    "10.3": "Output Control Events: Binary",
    "10.4": "Output Control Events: Analog",
}


def _part(text: str) -> tuple[int, str]:
    """Split one part of a procedure number into its number and its letter, as in 2a."""
    match = re.fullmatch(r"(\d+)([a-z]*)", text)
    if match is None:
        raise ValueError(f"{text!r} is not part of a procedure number")
    return int(match.group(1)), match.group(2)


def _key(procedure: str) -> list[tuple[int, str]]:
    """Sort procedure numbers as numbers, so 8.2 comes before 8.10 and 8.14.2b before 8.14.2c."""
    return [_part(part) for part in procedure.split(".")]


def section(procedure: str) -> str:
    """Return the section a procedure is in."""
    parts = procedure.split(".")
    two = f"{parts[0]}.{_part(parts[1])[0]}" if len(parts) > 1 else parts[0]
    return two if two in SECTIONS else parts[0]


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


def _numbered(values: dict[str, str], key: str) -> list[str]:
    """Return a list the harness saves as key.1, key.2 and so on."""
    found: list[str] = []
    while f"{key}.{len(found) + 1}" in values:
        found.append(values[f"{key}.{len(found) + 1}"])
    return found


def _skip_reason(procedure: str, detail: str) -> str:
    """Return a skip's reason as the record keeps it: the harness's, without its description."""
    if detail.startswith(_DISABLED):
        return detail[len(_DISABLED) :].split(": ", 1)[0]
    if detail.startswith(_NOT_APPLICABLE):
        return detail
    raise SystemExit(f"{procedure} was skipped for no reason the harness gives: {detail!r}")


def read_run(results: pathlib.Path) -> dict[str, dict[str, Any]]:
    """Read how each procedure of a run ended, as the record words it.

    The outcome and the warnings are from the harness's own result file, and the
    detail is from `outcomes.json`. A procedure whose two accounts disagree is an
    error, because one of them is not from this run.
    """
    summary_file = results / "outcomes.json"
    if not summary_file.is_file():
        raise SystemExit(f"{summary_file} is missing: the run did not finish")
    summary = json.loads(summary_file.read_text(encoding="utf-8"))["procedures"]

    run: dict[str, dict[str, Any]] = {}
    for directory in sorted(results.iterdir()):
        result_file = directory / "results.properties"
        if not directory.is_dir() or not result_file.is_file():
            continue
        saved = read_properties(result_file)
        result = saved.get("result", "")
        if result not in _RESULTS:
            raise SystemExit(f"{result_file} holds result={result!r}, which is not a result")
        outcome = _RESULTS[result]
        told = summary.get(directory.name)
        if told is None:
            raise SystemExit(f"{directory.name} has a result file and is not in {summary_file}")
        if told["outcome"] != outcome:
            raise SystemExit(
                f"{directory.name} is {outcome} in its result file and "
                f"{told['outcome']} in {summary_file}"
            )
        detail: str = told.get("detail", "")
        entry: dict[str, Any] = {"outcome": outcome, "detail": detail}
        if outcome == "skipped" and detail.startswith(_INCOMPLETE):
            entry["outcome"] = "not implemented"
        elif outcome == "skipped":
            entry["because"] = _skip_reason(directory.name, detail)
        elif outcome == "passed":
            entry["warnings"] = _numbered(saved, "warning")
            if entry["warnings"] != list(told.get("warnings", [])):
                raise SystemExit(
                    f"{directory.name} has warnings {entry['warnings']} in its result file and "
                    f"{told.get('warnings', [])} in {summary_file}"
                )
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


def subset_level(device: dict[str, str]) -> int:
    """Return the subset level a configuration sets."""
    level = device.get("outstation.subset.level", "")
    if not level.isdigit():
        raise SystemExit(f"device.ini sets outstation.subset.level to {level!r}, not a level")
    return int(level)


def _named(because: str) -> set[str]:
    """Return the options a skip reason names."""
    return {match["option"] for match in _CONDITION.finditer(because)}


def named_options(procedures: dict[str, dict[str, Any]]) -> set[str]:
    """Return every option a skip on record names."""
    return {
        name
        for entry in procedures.values()
        if entry.get("outcome") == "skipped"
        for name in _named(entry.get("because", ""))
    }


def options_off(device: dict[str, str], procedures: dict[str, dict[str, Any]]) -> list[str]:
    """Return the options the record depends on being off.

    Every `supports.*` option the configuration turns off, and every other one
    it turns off that a skip names.
    """
    named = named_options(procedures)
    return sorted(
        name
        for name, value in device.items()
        if value == "false" and (name.startswith("supports.") or name in named)
    )


def compare(
    expected: dict[str, Any],
    run: dict[str, dict[str, Any]],
    *,
    version: str,
    device: dict[str, str],
) -> list[str]:
    """Return every way a run and the files beside the record differ from the record."""
    problems: list[str] = []
    if expected.get("version") != version:
        problems.append(
            f"the record is of dnp3c {expected.get('version')} and pom.xml pins {version}"
        )
    if expected.get("level") != subset_level(device):
        problems.append(
            f"the record is of subset level {expected.get('level')} and device.ini sets "
            f"{subset_level(device)}"
        )

    reasons: dict[str, str] = expected.get("options", {})
    procedures: dict[str, dict[str, Any]] = expected.get("procedures", {})

    off = options_off(device, procedures)
    for name in off:
        if not reasons.get(name, "").strip():
            problems.append(f"{name} is off and the record gives no reason")
    for name in sorted(set(reasons) - set(off)):
        problems.append(
            f"the record gives a reason for {name}, which device.ini does not turn off or no "
            "procedure depends on"
        )
    for name in sorted(named_options(procedures) - set(device)):
        problems.append(f"a skip on record names {name}, which device.ini does not set")

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
        elif was["outcome"] == "skipped" and was.get("because") != now.get("because"):
            problems.append(
                f"{procedure} is on record as skipped because {was.get('because')} and was "
                f"skipped because {now.get('because')}"
            )
        elif was["outcome"] == "passed" and was.get("warnings", []) != now["warnings"]:
            problems.append(
                f"{procedure} is on record as passing with warnings {was.get('warnings', [])} and "
                f"passed with {now['warnings']}"
            )
        elif was["outcome"] in ("failed", "excluded") and not was.get("reason", "").strip():
            problems.append(f"{procedure} is on record as {was['outcome']} with no reason")
    return problems


def record(
    previous: dict[str, Any],
    run: dict[str, dict[str, Any]],
    *,
    version: str,
    device: dict[str, str],
) -> dict[str, Any]:
    """Build the record of a run, keeping the reasons the previous record gave."""
    old_reasons: dict[str, str] = previous.get("options", {})
    old_procedures: dict[str, dict[str, Any]] = previous.get("procedures", {})
    procedures: dict[str, dict[str, Any]] = {}
    for procedure, entry in run.items():
        kept: dict[str, Any] = {"outcome": entry["outcome"]}
        if entry["outcome"] == "skipped":
            kept["because"] = entry["because"]
        if entry["outcome"] == "passed" and entry["warnings"]:
            kept["warnings"] = entry["warnings"]
        if entry["outcome"] in ("failed", "excluded"):
            kept["reason"] = old_procedures.get(procedure, {}).get("reason", "")
        procedures[procedure] = kept
    return {
        "tool": "dnp3c",
        "version": version,
        "revision": previous.get("revision", REVISION),
        "level": subset_level(device),
        "options": {name: old_reasons.get(name, "") for name in options_off(device, procedures)},
        "procedures": procedures,
    }


def _following(procedure: str) -> str:
    """Return the procedure number that comes straight after this one: 8.2.4 after 8.2.3, 8.6.5b
    after 8.6.5a."""
    parts = procedure.split(".")
    number, letter = _part(parts[-1])
    parts[-1] = f"{number}{chr(ord(letter) + 1)}" if letter else str(number + 1)
    return ".".join(parts)


def _listed(procedures: list[str]) -> str:
    """Write procedure numbers as a list, with a run of three or more as "first to last"."""
    runs: list[list[str]] = []
    for procedure in sorted(procedures, key=_key):
        if runs and _following(runs[-1][-1]) == procedure:
            runs[-1].append(procedure)
        else:
            runs.append([procedure])
    return ", ".join(f"{run[0]} to {run[-1]}" if len(run) > 2 else ", ".join(run) for run in runs)


def _table(header: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "None."
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(lines)


def markdown(expected: dict[str, Any]) -> dict[str, str]:
    """Return the record as the tables the documentation carries, by name."""
    procedures: dict[str, dict[str, Any]] = expected["procedures"]
    reasons: dict[str, str] = expected["options"]

    def having(outcome: str, within: str | None = None) -> list[str]:
        return [
            procedure
            for procedure, entry in procedures.items()
            if entry["outcome"] == outcome and (within is None or section(procedure) == within)
        ]

    sections = sorted({section(p) for p in procedures}, key=_key)
    by_section = _table(
        ["Section", "Covers", "Passed", "Skipped", "Failed"],
        [
            [s, SECTIONS[s], *(_listed(having(o, s)) for o in ("passed", "skipped", "failed"))]
            for s in sections
        ],
    )

    def skipped(entry: dict[str, Any]) -> bool:
        return bool(entry["outcome"] == "skipped")

    def grouped(test: Any) -> dict[str, list[str]]:
        found: dict[str, list[str]] = {}
        for procedure, entry in procedures.items():
            if skipped(entry) and test(entry["because"]):
                found.setdefault(entry["because"], []).append(procedure)
        return found

    def skipped_for(name: str) -> list[str]:
        return [p for p, e in procedures.items() if skipped(e) and name in _named(e["because"])]

    off_table = _table(
        ["Option turned off", "Why", "Procedures skipped for it"],
        [
            [f"`{name}`", reason, _listed(skipped_for(name)) or "none"]
            for name, reason in sorted(reasons.items())
        ],
    )
    without = grouped(
        lambda because: (
            not because.startswith(_NOT_APPLICABLE) and not (_named(because) & set(reasons))
        )
    )
    for_devices_without = _table(
        ["Procedure", "Skipped because"],
        [[_listed(found), f"`{because}`"] for because, found in without.items()],
    )
    levels = grouped(lambda because: because.startswith(_NOT_APPLICABLE))
    other_levels = _table(
        ["Procedure", "Skipped because"],
        [[_listed(found), because[len(_NOT_APPLICABLE) :]] for because, found in levels.items()],
    )

    def reasoned(outcome: str) -> str:
        found: dict[str, list[str]] = {}
        for procedure in having(outcome):
            found.setdefault(procedures[procedure]["reason"], []).append(procedure)
        return _table(
            ["Procedure", "What happens, and which document it turns on"],
            [[_listed(group), reason] for reason, group in found.items()],
        )

    warned = _table(
        ["Procedure", "Warning"],
        [
            [procedure, warning]
            for procedure, entry in procedures.items()
            for warning in entry.get("warnings", [])
        ],
    )
    return {
        "sections": by_section,
        "failed": reasoned("failed"),
        "excluded": reasoned("excluded"),
        "warnings": warned,
        "options": off_table,
        "without": for_devices_without,
        "levels": other_levels,
        "not-implemented": _listed(having("not implemented")) or "None.",
    }


def main(argv: list[str] | None = None) -> int:
    """Compare a run with the record, or put the run on record. Return the exit status."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").partition("\n")[0])
    parser.add_argument(
        "--results",
        type=pathlib.Path,
        help="the run's folder; results/<revision>/L<level> beside this script when not given",
    )
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

    device = read_properties(args.device)
    version = pinned_version(args.pom)
    previous: dict[str, Any] = (
        json.loads(args.expected.read_text(encoding="utf-8")) if args.expected.is_file() else {}
    )
    revision = previous.get("revision", REVISION)
    results = args.results or HERE / "results" / revision / f"L{subset_level(device)}"
    run = read_run(results)

    if args.write:
        args.expected.write_text(
            json.dumps(record(previous, run, version=version, device=device), indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        print(f"wrote {args.expected}")
        previous = json.loads(args.expected.read_text(encoding="utf-8"))

    problems = compare(previous, run, version=version, device=device)
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
