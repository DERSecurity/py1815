"""The master's capture for the dissector job, and the validators that read it.

tshark and Suricata run only in the interoperability workflow. What can be
checked without them is checked here: that ``interop/master_capture.py``
writes a capture holding the requests the validators require, that its
summary counts what the file holds, and that the validators pass that capture
and fail one that is missing a request.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import struct
from collections import Counter

import pytest
import pytest_asyncio

from py1815.master.trace import RECEIVED, SENT, Trace
from py1815.server import OutstationServer
from py1815.session import Session

INTEROP = pathlib.Path(__file__).resolve().parents[1] / "interop"


def _script(name: str):
    """Load a script from ``interop/``, which is not a package."""
    spec = importlib.util.spec_from_file_location(f"interop_{name}", INTEROP / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _functions(pcap: bytes, port: int) -> Counter[str]:
    """Count the application functions in a capture, read from its packets alone."""
    trace = Trace()
    offset = 24
    while offset < len(pcap):
        _, _, length, _ = struct.unpack_from("<IIII", pcap, offset)
        packet = pcap[offset + 16 : offset + 16 + length]
        offset += 16 + length
        if packet[54:]:
            to_outstation = struct.unpack_from("!H", packet, 36)[0] == port
            trace.record(SENT if to_outstation else RECEIVED, packet[54:])
    return Counter(
        f"{entry.direction}:{entry.application['function']}"
        for entry in trace.since()
        if entry.application is not None
    )


@pytest_asyncio.fixture
async def fixture_outstation():
    """The interoperability fixture, served at the fragment size the job uses."""
    outstation = _script("outstation")
    controls = outstation.FixedControls()
    session = Session(
        outstation.FixedProvider(controls),
        control_provider=controls,
        events=outstation.seeded_events(),
        outstation_address=1024,
        master_address=1,
        max_response=36,
    )
    server = OutstationServer(session, bind="127.0.0.1:0")
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


@pytest_asyncio.fixture
async def written(fixture_outstation, tmp_path):
    """The capture and summary ``master_capture.py`` writes against the fixture."""
    args = argparse.Namespace(
        host="127.0.0.1",
        port=fixture_outstation.port,
        outstation_address=1024,
        master_address=1,
        pcap=str(tmp_path / "master.pcap"),
        summary=str(tmp_path / "master.json"),
        timeout=5.0,
    )
    assert await _script("master_capture").run(args) == 0
    summary = json.loads((tmp_path / "master.json").read_text(encoding="utf-8"))
    return (tmp_path / "master.pcap").read_bytes(), summary, fixture_outstation.port, tmp_path


class TestTheMastersCapture:
    @pytest.mark.asyncio
    async def test_it_holds_every_request_the_validators_require(self, written):
        pcap, _, port, _ = written
        functions = _functions(pcap, port)
        for name in ("CONFIRM", "READ", "WRITE", "DISABLE_UNSOLICITED"):
            assert functions[f"tx:{name}"], name
        assert functions["rx:RESPONSE"]
        assert functions["tx:WRITE"] == 2, "the restart indication cleared and the time written"

    @pytest.mark.asyncio
    async def test_its_summary_counts_what_the_file_holds(self, written):
        pcap, summary, port, _ = written
        functions = _functions(pcap, port)
        sent = sum(count for key, count in functions.items() if key.startswith("tx:"))
        assert summary == {
            "application_requests": sent - functions["tx:CONFIRM"],
            "confirms": functions["tx:CONFIRM"],
            "application_replies": functions["rx:RESPONSE"],
        }
        assert summary["confirms"] > 1, "each fragment of a multi-fragment response is confirmed"


def _tshark_rows(functions: list[str]) -> list[dict[str, str]]:
    """Rows as tshark prints them for frames carrying these application functions."""
    validate = _script("validate_pcap")
    rows = []
    for number, function in enumerate(functions, start=1):
        row = dict.fromkeys(validate.FIELDS, "")
        row.update(
            {
                "frame.number": str(number),
                "dnp.hdr.CRC.status": "1",
                "dnp.data_chunk.CRC.status": "1",
                "dnp3.al.func": function,
            }
        )
        rows.append(row)
    return rows


MASTER_FUNCTIONS = ["21", "129", "2", "129", "1", "129", "0", "1", "129", "2", "129"]
MASTER_SUMMARY = {"application_requests": 5, "confirms": 1, "application_replies": 5}


def _run_validate_pcap(monkeypatch, tmp_path, functions, summary, *flags) -> str | None:
    """Run ``validate_pcap.py`` with tshark's output given. Return its failure, or None."""
    validate = _script("validate_pcap")
    monkeypatch.setattr(validate, "run_tshark", lambda *_: _tshark_rows(functions))
    monkeypatch.setattr(validate.shutil, "which", lambda name: name)
    expect = tmp_path / "summary.json"
    expect.write_text(json.dumps(summary), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv", ["validate_pcap.py", "capture.pcap", "--expect", str(expect), *flags]
    )
    try:
        validate.main()
    except SystemExit as stop:
        assert stop.code == 1
        return "failed"
    return None


class TestTheWiresharkValidator:
    def test_the_masters_capture_passes(self, monkeypatch, tmp_path, capsys):
        failure = _run_validate_pcap(
            monkeypatch, tmp_path, MASTER_FUNCTIONS, MASTER_SUMMARY, "--kind", "master"
        )
        assert failure is None, capsys.readouterr().err
        assert "5 requests, 1 confirmations and 5 responses" in capsys.readouterr().out

    def test_a_request_the_dissector_did_not_find_fails(self, monkeypatch, tmp_path, capsys):
        dropped = list(MASTER_FUNCTIONS)
        dropped.remove("1")
        assert _run_validate_pcap(
            monkeypatch, tmp_path, dropped, MASTER_SUMMARY, "--kind", "master"
        )
        assert "the master sent 5 requests and this dissector found 4" in capsys.readouterr().err

    def test_a_confirmation_the_dissector_did_not_find_fails(self, monkeypatch, tmp_path, capsys):
        summary = {**MASTER_SUMMARY, "confirms": 2}
        assert _run_validate_pcap(
            monkeypatch, tmp_path, MASTER_FUNCTIONS, summary, "--kind", "master"
        )
        assert "the master sent 2 confirmations and this dissector found 1" in (
            capsys.readouterr().err
        )

    def test_a_required_function_that_is_absent_fails(self, monkeypatch, tmp_path, capsys):
        functions = [function for function in MASTER_FUNCTIONS if function != "21"]
        summary = {**MASTER_SUMMARY, "application_requests": 4}
        assert _run_validate_pcap(monkeypatch, tmp_path, functions, summary, "--kind", "master")
        assert "disable unsolicited" in capsys.readouterr().err

    def test_the_masters_capture_is_not_the_sweeps(self, monkeypatch, tmp_path, capsys):
        assert _run_validate_pcap(monkeypatch, tmp_path, MASTER_FUNCTIONS, MASTER_SUMMARY)
        assert "missing" in capsys.readouterr().err


def _eve(path: pathlib.Path, records: list[tuple[str, int]]) -> None:
    lines = [
        json.dumps(
            {"event_type": "dnp3", "dnp3": {"type": kind, "application": {"function_code": code}}}
        )
        for kind, code in records
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


MASTER_RECORDS = [
    ("request", 21),
    ("response", 129),
    ("request", 2),
    ("response", 129),
    ("request", 1),
    ("response", 129),
    ("request", 1),
    ("response", 129),
    ("request", 2),
    ("response", 129),
]


def _run_validate_suricata(monkeypatch, tmp_path, records, summary, *flags) -> str | None:
    validate = _script("validate_suricata")
    eve = tmp_path / "eve.json"
    _eve(eve, records)
    expect = tmp_path / "summary.json"
    expect.write_text(json.dumps(summary), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv", ["validate_suricata.py", str(eve), "--expect", str(expect), *flags]
    )
    try:
        validate.main()
    except SystemExit as stop:
        assert stop.code == 1
        return "failed"
    return None


class TestTheSuricataValidator:
    def test_the_masters_capture_passes(self, monkeypatch, tmp_path, capsys):
        failure = _run_validate_suricata(
            monkeypatch, tmp_path, MASTER_RECORDS, MASTER_SUMMARY, "--kind", "master"
        )
        assert failure is None, capsys.readouterr().err

    def test_a_request_the_parser_dropped_fails(self, monkeypatch, tmp_path, capsys):
        dropped = list(MASTER_RECORDS)
        dropped.remove(("request", 1))
        assert _run_validate_suricata(
            monkeypatch, tmp_path, dropped, MASTER_SUMMARY, "--kind", "master"
        )
        assert "the master sent 5 requests" in capsys.readouterr().err

    def test_a_required_function_that_is_absent_fails(self, monkeypatch, tmp_path, capsys):
        records = [record for record in MASTER_RECORDS if record != ("request", 21)]
        summary = {**MASTER_SUMMARY, "application_requests": 4}
        assert _run_validate_suricata(monkeypatch, tmp_path, records, summary, "--kind", "master")
        assert "disable unsolicited" in capsys.readouterr().err

    def test_the_masters_capture_is_not_the_sweeps(self, monkeypatch, tmp_path, capsys):
        assert _run_validate_suricata(monkeypatch, tmp_path, MASTER_RECORDS, MASTER_SUMMARY)
        assert "absent" in capsys.readouterr().err
