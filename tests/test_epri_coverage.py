"""Every procedure of EPRI's DER profile test report, and what was done about it.

``test_epri_der_procedures.py`` carries the procedures out and names its
tests for them. This file is the other half: a catalog of the procedures of
EPRI report 3002016144, each either pointing at its tests or saying why it
does not apply, with checks that keep the two in step. It also records, in
one place, where the suite departs from what the report says and why.

The report is EPRI's and is not reproduced. Its procedures are referred to by
the identifiers it gives them.
"""

from __future__ import annotations

import ast
import pathlib

from test_epri_der_procedures import IMPLEMENTED, MODES

_PROCEDURES = pathlib.Path(__file__).resolve().parent / "test_epri_der_procedures.py"

#: Every procedure in the report, in its order: the function tests, the
#: generic curve tests, the mode tests and the scheduling test.
ALL = (
    "MON-001",
    "ALARM-001",
    "CONN-001",
    "SERV-001",
    "OP-001",
    "CURVE-001",
    "CURVE-002",
    "CURVE-003",
    *MODES,
    "SCHED-001",
)

#: Procedures with tests of their own, by what those tests' names start with.
TESTED = {
    "MON-001": "test_mon_001_",
    "ALARM-001": "test_alarm_001_",
    "CONN-001": "test_conn_001_",
    "SERV-001": "test_serv_001_",
    "OP-001": "test_op_001_",
    "CURVE-001": "test_curve_001_",
    "CURVE-002": "test_curve_002_",
    "CURVE-003": "test_curve_003_",
}

#: Procedures that do not apply to this outstation, and why.
NOT_APPLICABLE = {
    "SCHED-001": (
        "schedules are resolved in the point map and not simulated, and the procedure "
        "itself applies only where the schedule selector is supported"
    ),
}

#: Where the suite does something other than what the report says. The report
#: was written against the application note that IEEE 1815.2 replaced, and
#: each of these follows the standard.
DEPARTURES = {
    "CURVE-002": (
        "the report expects the error the application note named for a write to a locked "
        "curve; the standard recommends the AUTOMATION_INHIBIT control status, which is "
        "what is returned and checked"
    ),
    "CURVE-003": (
        "neither document names the error for a curve of the wrong type; NOT_SUPPORTED is "
        "returned and checked"
    ),
    "SERV-001": (
        "the input each command is read back at is taken from the IEEE tables, which pair "
        "the stop command with a different input than the report's table does; the states "
        "the report names are checked as well"
    ),
    "mode tests": (
        "the report assumes each function is running and checks its inputs are ONLINE; the "
        "function is enabled first so that holds, and its inputs are also checked to be "
        "sent without the ONLINE flag while it is disabled, as the standard requires"
    ),
    "conformance statement": (
        "the report takes the list of supported points from a statement the vendor fills "
        "in; here a point is supported if the outstation serves it"
    ),
}


def _tests() -> list[str]:
    tree = ast.parse(_PROCEDURES.read_text(encoding="utf-8"))
    return [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    ]


def test_every_procedure_is_accounted_for_once():
    modes = set(MODES)
    accounted = [*TESTED, *NOT_APPLICABLE, *modes]
    assert sorted(accounted) == sorted(ALL)
    assert len(ALL) == len(set(ALL)) == 30


def test_every_procedure_listed_as_tested_has_a_test():
    names = _tests()
    for procedure, prefix in TESTED.items():
        assert any(name.startswith(prefix) for name in names), f"{procedure} has no test"
    assert "test_mode" in names, "the mode procedures are one parametrized test"


def test_every_test_belongs_to_a_procedure():
    """A test may not claim a procedure the catalog has not accounted for."""
    allowed = (*TESTED.values(), "test_mode", "test_the_")
    stray = [name for name in _tests() if not name.startswith(allowed)]
    assert not stray


def test_the_mode_procedures_are_the_reports_twenty_one():
    assert len(MODES) == 21
    assert len(set(MODES.values())) == 21
    assert set(MODES) >= IMPLEMENTED


def test_every_exclusion_and_departure_gives_a_reason():
    for reason in (*NOT_APPLICABLE.values(), *DEPARTURES.values()):
        assert len(reason.split()) >= 8
