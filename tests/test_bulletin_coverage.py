"""Every technical bulletin and application note, and what was done about it.

The DNP Users Group corrects and extends the base standard through technical
bulletins (TB) and application notes (AN). This is the catalog of them: each
either points at the tests that check what it asks of an outstation, or says
why it asks nothing of this one. Two checks keep the catalog and the tests in
step, as they do for the certification procedures.

The documents are the Users Group's and are not reproduced. They are named
here by their numbers and titles.
"""

from __future__ import annotations

import ast
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent

#: Documents with tests: the file that holds them and what their names start with.
TESTED: dict[str, tuple[str, str]] = {
    "TB2013-002 special use addresses": ("test_technical_bulletins.py", "test_tb2013_002_"),
    "TB2013-003 transport reception state table": (
        "test_technical_bulletins.py",
        "test_tb2013_003_",
    ),
    "TB2014-002 control-related status codes": ("test_technical_bulletins.py", "test_tb2014_002_"),
    "TB2016-001 indications 2.0, 2.1 and 2.2": ("test_technical_bulletins.py", "test_tb2016_001_"),
    "TB2015-002 unsolicited response behavior": (
        "test_technical_bulletins.py",
        "test_tb2015_002_",
    ),
    "TB2016-003 subset parsing tables": ("test_subset_tables.py", "test_tb2016_003_"),
    "TB2016-004 unsolicited reporting in constrained environments": (
        "test_technical_bulletins.py",
        "test_tb2016_004_",
    ),
    "TB2017-003 event reporting requirements": ("test_ied_8_inputs.py", "test_8_15_3_"),
    "TB2018-001 time management, common time and event ordering": (
        "test_technical_bulletins.py",
        "test_tb2018_001_",
    ),
    "TB2018-002 link layer synchronization": ("test_ied_6_7_link_transport.py", "test_6_1_2_"),
    "TB2018-003 leap seconds": ("test_technical_bulletins.py", "test_tb2018_003_"),
    "TB2018-004 analog input processing rules": (
        "test_technical_bulletins.py",
        "test_tb2018_004_",
    ),
    "AN2012-002 DNP3 over UDP": ("test_ied_9_network.py", "test_9_5_1_5_"),
    "AN2012-004 LAN time synchronization": ("test_ied_8_indications.py", "test_8_7_2_"),
    "AN2013-004 validation of incoming data": ("test_technical_bulletins.py", "test_an2013_004b_"),
    "AN2014-001 disabling function codes": ("test_technical_bulletins.py", "test_an2014_001_"),
    "AN2015-001 default configuration parameters": (
        "test_technical_bulletins.py",
        "test_an2015_001_",
    ),
    "AN2018-001 DER profile": ("test_epri_der_procedures.py", "test_mode"),
    "AN2022-01 device profile how-to": (
        "test_profile_device_profile.py",
        "test_the_simulated_der_validates",
    ),
}

#: Documents that ask nothing of this outstation, and why.
NOT_APPLICABLE: dict[str, str] = {
    "TB2013-004 additional nameplate attributes": "device attributes are not implemented",
    "TB2014-001 errata": "the corrections concern device attributes, which are not implemented",
    "TB2014-005 device profile schema correction": (
        "the document is generated for a later schema version than the one corrected"
    ),
    "TB2015-001 object groups 110 to 115": "octet string objects are not implemented",
    "TB2016-002 secure authentication deficiencies": "secure authentication is not implemented",
    "TB2016-005 invalid floating point in device attributes": (
        "device attributes are not implemented"
    ),
    "TB2017-001 certification procedure corrections": (
        "corrects the local mode tests, and outputs here have no local mode"
    ),
    "TB2017-002 asymmetric update key change": "secure authentication is not implemented",
    "TB2017-004 ASN.1 schema erratum": "secure authentication is not implemented",
    "TB2017-005 database synchronization and integrity polling": (
        "a requirement on masters; the integrity poll it relies on is in the procedures"
    ),
    "TB2017-006 erratum to four figures": "a correction to figures that changes no behavior",
    "TB2017-007 data type codes in device attributes": "device attributes are not implemented",
    "AN2004-001 system management data points": "advice on point lists for a kind of device",
    "AN2006-001 writing application notes": "about writing application notes",
    "AN2010-001 handling state event data": "advice to system designers on event buffers",
    "AN2011-001 photovoltaic profile": "superseded by the DER profile",
    "AN2012-001 managing secure authentication updates": (
        "secure authentication is not implemented"
    ),
    "AN2013-001 advanced photovoltaic profile": "superseded by the DER profile",
    "AN2013-002 secure authentication tutorial": "secure authentication is not implemented",
    "AN2013-003 electric vehicle and storage profile": "a different profile from the one served",
    "AN2014-002 secure management of configuration": (
        "configuration is not reachable over the protocol at all"
    ),
    "AN2017-001 secure authentication procurement": "secure authentication is not implemented",
    "AN2018-002 conformance procurement guidelines": "advice to purchasers",
}


def _tests(name: str) -> list[str]:
    tree = ast.parse((_HERE / name).read_text(encoding="utf-8"))
    return [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    ]


def test_every_document_listed_as_tested_has_a_test():
    for document, (file, prefix) in TESTED.items():
        assert any(name.startswith(prefix) for name in _tests(file)), f"{document} has no test"


def test_every_bulletin_test_belongs_to_a_listed_document():
    """A test may not cite a document the catalog has not accounted for."""
    prefixes = tuple(
        prefix for file, prefix in TESTED.values() if file == "test_technical_bulletins.py"
    )
    stray = [
        name for name in _tests("test_technical_bulletins.py") if not name.startswith(prefixes)
    ]
    assert not stray


def test_no_document_is_both_tested_and_excluded():
    assert not {name.split()[0] for name in TESTED} & {name.split()[0] for name in NOT_APPLICABLE}


def test_every_exclusion_gives_a_reason():
    assert all(len(reason.split()) >= 3 for reason in NOT_APPLICABLE.values())


def test_a_document_is_listed_once():
    """So that none is counted under two headings."""
    numbers = [name.split()[0] for name in (*TESTED, *NOT_APPLICABLE)]
    assert len(numbers) == len(set(numbers))
    assert all(number[:2] in ("TB", "AN") for number in numbers)
