"""Check this outstation's tables against IEEE Std 1815-2012's own tables.

The codes, names and field widths in `conformance/ieee-1815-2012.json` were read
out of the standard by `scripts/extract_conformance.py`. These tests diff this
package against that file, so a code the standard assigns and this package does
not name -- or a field width that disagrees with the standard's -- fails here
rather than in somebody else's master.

Where this package diverges on purpose the divergence is listed below with its
reason. Anything not listed is a failure, which is the point: an undocumented
divergence cannot pass quietly.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

from py1815 import link
from py1815.application import (
    _INDEX_WIDTHS,  # the widths under test
    FunctionCode,
    IIN2Bit,
    IINBit,
    QualifierCode,
    RequestError,
    parse_request,
)
from py1815.session import _NO_RESPONSE_FUNCTIONS, _SUPPORTED_FUNCTIONS, Session

TABLES = pathlib.Path(__file__).resolve().parent.parent / "conformance" / "ieee-1815-2012.json"

OUTSTATION = 1024
MASTER = 1

#: Codes the standard abbreviates and this package spells out. The wire value is
#: what has to agree; the identifier is ours to make readable.
FUNCTION_SPELLING = {
    "INITIALIZE_APPL": "INITIALIZE_APPLICATION",
    "START_APPL": "START_APPLICATION",
    "STOP_APPL": "STOP_APPLICATION",
    "SAVE_CONFIG": "SAVE_CONFIGURATION",
    "AUTHENTICATE_REQ": "AUTH_REQUEST",
    "AUTH_REQ_NO_ACK": "AUTH_REQUEST_NO_ACK",
    "AUTHENTICATE_RESP": "AUTH_RESPONSE",
}

#: The same, for the indication bits.
IIN_SPELLING = {
    "NO_FUNC_CODE_SUPPORT": "FUNC_NOT_SUPPORTED",
    "PARAMETER_ERROR": "PARAM_ERROR",
}

#: IIN2.6 and IIN2.7 are reserved and always 0, so there is nothing to set and
#: no name worth having. Every other bit in the table is named.
UNNAMED_IIN_BITS = {"2.6", "2.7"}


@pytest.fixture(scope="module")
def tables() -> dict:
    assert TABLES.is_file(), f"{TABLES} is missing"
    return json.loads(TABLES.read_text(encoding="utf-8"))["tables"]


def _expected_name(standard_name: str, spelling: dict[str, str]) -> str:
    return spelling.get(standard_name, standard_name)


def _function_codes() -> dict[int, dict]:
    """Table 4-2 keyed by integer code, for use at collection time."""
    loaded = json.loads(TABLES.read_text(encoding="utf-8"))
    return {int(code): row for code, row in loaded["tables"]["4-2"]["function_codes"].items()}


class _Provider:
    """The smallest read provider a session will accept."""

    def read(self, headers):
        return b""


def _receive(fragment: bytes) -> list[bytes]:
    """Application fragments a fresh session replies with to one request."""
    session = Session(_Provider(), outstation_address=OUTSTATION, master_address=MASTER)
    control = link.control_byte(
        from_master=True, primary=True, function=link.PrimaryFunction.UNCONFIRMED_USER_DATA
    )
    frame = link.build(control, destination=OUTSTATION, source=MASTER, payload=b"\xc0" + fragment)
    reply = session.receive(frame)
    return [f.payload[1:] for f in link.FrameReader().feed(reply) if f.payload]


# ------------------------------------------------- Table 4-2: function codes


def test_every_assigned_function_code_is_named(tables: dict) -> None:
    """A code the standard assigns has to have a name here.

    An unnamed code cannot be answered "function not supported" as a named,
    unimplemented function -- it is refused as unrecognized instead, which tells
    a master something different about whether to retry.
    """
    ours = {int(member) for member in FunctionCode}
    rows = tables["4-2"]["function_codes"]
    missing = sorted(int(code) for code in rows if int(code) not in ours)
    assert not missing, "codes in Table 4-2 that FunctionCode does not name: " + ", ".join(
        f"{code} (0x{code:02X}) {rows[str(code)]['name']}" for code in missing
    )


def test_no_function_code_is_invented(tables: dict) -> None:
    """A name here has to correspond to a code the standard assigns."""
    theirs = {int(code) for code in tables["4-2"]["function_codes"]}
    invented = sorted(member for member in FunctionCode if int(member) not in theirs)
    assert not invented, "FunctionCode members absent from Table 4-2: " + ", ".join(
        f"{member.name} = 0x{int(member):02X}" for member in invented
    )


def test_function_code_names_agree(tables: dict) -> None:
    """Same code, same name -- allowing for the spellings listed above."""
    ours = {int(member): member.name for member in FunctionCode}
    differing = {
        int(code): (row["name"], ours[int(code)])
        for code, row in tables["4-2"]["function_codes"].items()
        if int(code) in ours and ours[int(code)] != _expected_name(row["name"], FUNCTION_SPELLING)
    }
    assert not differing, (
        "names that differ without being listed in FUNCTION_SPELLING: "
        + ", ".join(
            f"0x{code:02X} standard={theirs} ours={mine}"
            for code, (theirs, mine) in sorted(differing.items())
        )
    )


def test_the_no_response_set_matches_table_4_2(tables: dict) -> None:
    """Exactly the codes the table says draw no response are treated that way.

    A code missing from this set gets answered when the standard says the
    outstation shall stay silent, and an extra one goes unanswered when a master
    is waiting.
    """
    theirs = {
        int(code)
        for code, row in tables["4-2"]["function_codes"].items()
        if not row["sends_response"]
    }
    ours = {int(member) for member in _NO_RESPONSE_FUNCTIONS}
    assert ours == theirs, (
        f"no-response codes here {sorted(hex(code) for code in ours)}, "
        f"Table 4-2 gives {sorted(hex(code) for code in theirs)}"
    )


@pytest.mark.parametrize(
    "code",
    sorted(code for code, row in _function_codes().items() if not row["sends_response"]),
    ids=lambda code: f"0x{code:02X}",
)
def test_a_no_response_function_draws_silence(code: int) -> None:
    """Nothing goes back, not even a refusal.

    These are the codes whose whole point is that the master is not waiting, so
    a refusal is a frame it has no reason to read.
    """
    assert _receive(bytes([0xC0, code])) == []


@pytest.mark.parametrize(
    "code",
    sorted(
        code
        for code, row in _function_codes().items()
        if row["sends_response"]
        and code < 0x80
        and code not in {int(function) for function in _SUPPORTED_FUNCTIONS}
    ),
    ids=lambda code: f"0x{code:02X}",
)
def test_an_unimplemented_function_is_refused_not_dropped(code: int) -> None:
    """A code this outstation does not implement earns IIN2.0, not silence.

    Silence looks like a lost frame, so a master retries it; a refusal tells it
    not to. This runs over every assigned request code rather than a chosen few,
    so a code added to the table is covered without anybody remembering to.
    """
    fragments = _receive(bytes([0xC0, code]))
    assert fragments, f"0x{code:02X} drew no reply at all"
    assert fragments[0][3] & IIN2Bit.FUNC_NOT_SUPPORTED, f"0x{code:02X} was not refused"


# ----------------------------------------------------- Table 4-3: IIN bits


def test_every_indication_bit_is_named(tables: dict) -> None:
    """Every settable bit in Table 4-3 has a name in one of the two enums."""
    named = {member.name for member in IINBit} | {member.name for member in IIN2Bit}
    missing = sorted(
        f"IIN{bit} {name}"
        for bit, name in tables["4-3"]["iin_bits"].items()
        if bit not in UNNAMED_IIN_BITS and _expected_name(name, IIN_SPELLING) not in named
    )
    assert not missing, "bits in Table 4-3 with no name here: " + ", ".join(missing)


@pytest.mark.parametrize("octet, enum", [(1, IINBit), (2, IIN2Bit)])
def test_indication_bit_positions(tables: dict, octet: int, enum: type) -> None:
    """A named bit carries the mask for the position the standard gives it.

    These enums hold masks rather than positions, so the value has to be
    `1 << position`. Getting this wrong sets a neighbouring indication.
    """
    expected = {
        _expected_name(name, IIN_SPELLING): 1 << int(bit.split(".")[1])
        for bit, name in tables["4-3"]["iin_bits"].items()
        if bit.startswith(f"{octet}.") and bit not in UNNAMED_IIN_BITS
    }
    ours = {member.name: int(member) for member in enum}
    for name, mask in expected.items():
        assert name in ours, f"IIN{octet} bit {name} is not named"
        assert ours[name] == mask, (
            f"{name} is 0x{ours[name]:02X}, Table 4-3 puts it at 0x{mask:02X}"
        )


@pytest.mark.parametrize("octet, enum", [(1, IINBit), (2, IIN2Bit)])
def test_no_indication_bit_is_invented(tables: dict, octet: int, enum: type) -> None:
    """A bit named here has to be one Table 4-3 defines for this octet."""
    theirs = {
        _expected_name(name, IIN_SPELLING)
        for bit, name in tables["4-3"]["iin_bits"].items()
        if bit.startswith(f"{octet}.")
    }
    invented = sorted(member.name for member in enum if member.name not in theirs)
    assert not invented, f"IIN{octet} names absent from Table 4-3: " + ", ".join(invented)


# ------------------------------- Tables 4-4, 4-5, 4-6: qualifier and range


def test_every_accepted_qualifier_is_valid(tables: dict) -> None:
    """Accepting a qualifier the standard does not permit is a defect.

    Table 4-6 is the whole permitted set. This package implements a subset of
    it, which is allowed; accepting something outside it is not.
    """
    valid = set(tables["4-6"]["qualifiers"])
    invalid = sorted(member for member in QualifierCode if int(member) not in valid)
    assert not invalid, "qualifiers Table 4-6 does not permit: " + ", ".join(
        f"{member.name} = 0x{int(member):02X}" for member in invalid
    )


def test_no_accepted_qualifier_uses_a_reserved_nibble(tables: dict) -> None:
    """Neither half of an accepted qualifier may be a reserved code."""
    prefixes = tables["4-4"]["prefix_codes"]
    ranges = tables["4-5"]["range_codes"]
    for member in QualifierCode:
        prefix = prefixes[str(int(member) >> 4)]
        specifier = ranges[f"{int(member) & 0xF:X}"]
        assert prefix["kind"] != "reserved", f"{member.name}: prefix {int(member) >> 4} is reserved"
        assert specifier["kind"] != "reserved", f"{member.name}: range code is reserved"


def test_index_prefix_widths_match_table_4_4(tables: dict) -> None:
    """The index width read per object is the width the prefix code states.

    Reading a two-octet index as one octet does not fail -- it silently walks
    off by a byte for the rest of the list, which is why this is pinned.
    """
    prefixes = tables["4-4"]["prefix_codes"]
    for member in QualifierCode:
        prefix = prefixes[str(int(member) >> 4)]
        if prefix["kind"] == "index":
            assert member in _INDEX_WIDTHS, (
                f"{member.name} prefixes each object with a {prefix['octets']}-octet index "
                "and has no width declared"
            )
            assert _INDEX_WIDTHS[member] == prefix["octets"], (
                f"{member.name}: width {_INDEX_WIDTHS[member]}, Table 4-4 states {prefix['octets']}"
            )
        else:
            assert member not in _INDEX_WIDTHS, (
                f"{member.name} has an index width but its prefix code is {prefix['kind']!r}"
            )


# ------------------------------------------- what the sweep actually covers

SWEEP = pathlib.Path(__file__).resolve().parents[1] / "interop" / "sweep.py"


def _sweep():
    """Load ``interop/sweep.py``, which is a script rather than a package.

    It imports a sibling script by bare name, the way a script run from that
    directory would, so the directory goes on the path first. It also declares
    dataclasses under postponed annotations, and `dataclasses` resolves those
    through `sys.modules`, so the module has to be registered there before it
    runs rather than only after.
    """
    spec = importlib.util.spec_from_file_location("interop_sweep", SWEEP)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(SWEEP.parent))
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(SWEEP.parent))
        sys.modules.pop(spec.name, None)
    return module


@pytest.mark.skipif(not SWEEP.is_file(), reason="interop/ is not in a source distribution")
def test_the_sweep_covers_every_assigned_request_code(tables: dict) -> None:
    """The interoperability sweep has to exercise every request code in Table 4-2.

    Its cases are written out one per code, so a code nobody wrote a case for is
    simply not swept -- and it passes, because there is no case to fail. This is
    the check that notices, rather than the sweep noticing its own gap.
    """
    # The link-layer cases carry no application payload, so there is no function
    # code in them to count.
    swept = {case.payload[1] for case in _sweep().CASES if len(case.payload) >= 2}
    assigned = {
        int(code) for code, row in tables["4-2"]["function_codes"].items() if int(code) < 0x80
    }
    uncovered = sorted(assigned - swept)
    assert not uncovered, "request codes in Table 4-2 with no sweep case: " + ", ".join(
        f"0x{code:02X} {tables['4-2']['function_codes'][str(code)]['name']}" for code in uncovered
    )


def _read_request(qualifier: QualifierCode, range_octets: int) -> bytes:
    """A READ of group 1 variation 2 with `range_octets` of range field."""
    return bytes([0xC0, int(FunctionCode.READ), 0x01, 0x02, int(qualifier)]) + bytes(range_octets)


@pytest.mark.parametrize("qualifier", list(QualifierCode), ids=lambda q: q.name)
def test_range_field_width_matches_table_4_5(tables: dict, qualifier: QualifierCode) -> None:
    """The parser consumes exactly the octets Table 4-5 gives the range field.

    Checked from both sides: that width parses, and one octet short of it does
    not. A parser that read too few would leave the remainder to be misread as
    the next object header.
    """
    specifier = tables["4-5"]["range_codes"][f"{int(qualifier) & 0xF:X}"]
    octets = specifier["octets"]
    assert octets is not None, f"{qualifier.name} maps to a reserved range code"

    request = parse_request(_read_request(qualifier, octets))
    assert len(request.headers) == 1, (
        f"{qualifier.name}: {octets} octets of range field should be exactly one header"
    )

    if octets:
        with pytest.raises(RequestError):
            parse_request(_read_request(qualifier, octets - 1))
