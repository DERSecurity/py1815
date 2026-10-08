"""The ``py1815-der`` command line."""

from __future__ import annotations

import asyncio
import io
import json
import threading
import zipfile

import pytest
from profile_fixtures import REAL_TABLES, analog, for_reference_der, row

from py1815.profile import cli, der, extract, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer


@pytest.fixture
def tables(tmp_path, monkeypatch):
    """Synthetic tables on disk, named by the environment as a user's would be."""
    path = tmp_path / load.TABLES_NAME
    path.write_text(json.dumps(for_reference_der()), encoding="utf-8")
    monkeypatch.setenv(load.TABLES_VARIABLE, str(path))
    return path


class TestWithoutTables:
    @pytest.mark.parametrize("command", [["run"], ["points"]])
    def test_the_command_says_how_to_get_them(self, command, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "absent.json"))
        assert cli.main(command) == 1
        assert "py1815-der tables fetch" in capsys.readouterr().err


class TestPoints:
    def test_it_lists_what_the_simulated_der_serves(self, tables, capsys):
        assert cli.main(["points"]) == 0
        listed = capsys.readouterr().out.splitlines()
        assert any(line.startswith("BO0 ") for line in listed)
        assert any(line.startswith("CTR3") for line in listed)

    def test_a_path_on_the_command_line_wins_over_the_environment(
        self, tables, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "absent.json"))
        assert cli.main(["points", "--tables", str(tables)]) == 0

    @pytest.fixture
    def wider_tables(self, tables):
        """The tables with two optional points the simulated DER does not bind."""
        document = for_reference_der()
        document["points"]["AI"].append(analog("Not simulated", 64000, event_class=2))
        document["points"]["BI"].append(row("Also not simulated", 64001, event_class=1))
        tables.write_text(json.dumps(document), encoding="utf-8")
        return tables

    def test_coverage_reports_the_points_it_does_not_serve_as_well(self, wider_tables, capsys):
        assert cli.main(["points"]) == 0
        plain = capsys.readouterr().out
        assert "Not simulated" not in plain, "the plain listing is of what is served"
        assert cli.main(["points", "--coverage"]) == 0
        report = capsys.readouterr().out.splitlines()
        (missing,) = [line for line in report if line.startswith("AI64000 ")]
        assert "absent" in missing
        (output,) = [line for line in report if line.startswith("BO0 ")]
        assert "bound" in output
        assert any("mandatory" in line for line in report), "and how far it is from conformant"

    def test_coverage_is_the_report_the_outstation_gives(self, wider_tables, capsys):
        assert cli.main(["points", "--coverage"]) == 0
        printed = capsys.readouterr().out
        outstation = der.build(load.load(wider_tables)).outstation
        assert printed == outstation.coverage().render() + "\n"


class TestTablesBuild:
    def test_a_missing_workbook_is_reported(self, tmp_path, capsys):
        assert cli.main(["tables", "build", str(tmp_path / "absent.xlsx")]) == 2
        assert "no such file" in capsys.readouterr().err

    def test_a_file_that_is_not_the_workbook_is_reported(self, tmp_path, capsys):
        workbook = tmp_path / "other.xlsx"
        workbook.write_text("not a workbook", encoding="utf-8")
        out = tmp_path / "tables.json"
        assert cli.main(["tables", "build", str(workbook), "--out", str(out)]) == 1
        assert "could not read" in capsys.readouterr().err
        assert not out.exists(), "nothing is written from a workbook that did not parse"


def _archive(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class TestTablesFetch:
    def test_the_workbook_is_found_inside_the_download(self):
        data = _archive({"docs/1815.2_Profile Companion Data Point Tables.xlsx": b"workbook"})
        name, content = cli._workbook_from_archive(data)
        assert name == "1815.2_Profile Companion Data Point Tables.xlsx"
        assert content == b"workbook"

    def test_the_tables_are_preferred_over_another_workbook(self):
        data = _archive({"other.xlsx": b"no", "Data Point Tables.xlsx": b"yes"})
        assert cli._workbook_from_archive(data)[1] == b"yes"

    @pytest.mark.parametrize(
        "members",
        [
            pytest.param({"readme.txt": b""}, id="no workbook"),
            pytest.param({"a.xlsx": b"", "b.xlsx": b""}, id="two candidates"),
        ],
    )
    def test_an_archive_without_exactly_one_candidate_is_refused(self, members):
        with pytest.raises(OSError):
            cli._workbook_from_archive(_archive(members))

    def test_a_workbook_that_inflates_past_the_cap_is_refused(self, monkeypatch):
        """The cap bounds the archive; this bounds what comes out of it."""
        data = _archive({"Data Point Tables.xlsx": b"x" * 64})
        monkeypatch.setattr(cli, "_MAX_DOWNLOAD", 63)
        with pytest.raises(OSError, match="exceeds"):
            cli._workbook_from_archive(data)
        monkeypatch.setattr(cli, "_MAX_DOWNLOAD", 64)
        assert cli._workbook_from_archive(data)[1] == b"x" * 64

    def test_an_oversized_workbook_is_a_failed_download(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(
            cli, "_download", lambda _url: _archive({"Data Point Tables.xlsx": b"x" * 64})
        )
        monkeypatch.setattr(cli, "_MAX_DOWNLOAD", 63)
        out = tmp_path / "tables.json"
        assert cli.main(["tables", "fetch", "--out", str(out)]) == 1
        assert "download failed" in capsys.readouterr().err
        assert not (tmp_path / "Data Point Tables.xlsx").exists()

    def test_a_failed_download_says_how_to_do_it_by_hand(self, tmp_path, monkeypatch, capsys):
        def refuse(_url: str) -> bytes:
            raise OSError("no route to host")

        monkeypatch.setattr(cli, "_download", refuse)
        out = tmp_path / "tables.json"
        assert cli.main(["tables", "fetch", "--out", str(out)]) == 1
        message = capsys.readouterr().err
        assert "no route to host" in message and "tables build" in message
        assert not out.exists()

    def test_a_download_that_is_not_an_archive_is_a_failed_download(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(cli, "_download", lambda _url: b"<html>moved</html>")
        assert cli.main(["tables", "fetch", "--out", str(tmp_path / "t.json")]) == 1
        assert "download failed" in capsys.readouterr().err

    def test_the_downloaded_workbook_is_kept_beside_the_tables(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(
            cli, "_download", lambda _url: _archive({"Data Point Tables.xlsx": b"junk"})
        )
        out = tmp_path / "kept" / "tables.json"
        # The content is not a workbook, so reading it fails; the download
        # itself is still on disk for the user to inspect.
        assert cli.main(["tables", "fetch", "--out", str(out)]) == 1
        assert (out.parent / "Data Point Tables.xlsx").read_bytes() == b"junk"
        assert not out.exists()


@pytest.mark.skipif(not REAL_TABLES.is_file(), reason="the IEEE tables are generated locally")
class TestTheWrittenTables:
    def test_what_the_extractor_serializes_loads_back(self, tmp_path):
        document = json.loads(REAL_TABLES.read_text(encoding="utf-8"))
        path = tmp_path / "tables.json"
        path.write_text(extract.serialize(document), encoding="utf-8")
        assert len(load.load(path)) > 1000
        assert "profile version" in extract.summary(document)

    def test_two_extractions_of_one_workbook_compare_equal(self):
        document = json.loads(REAL_TABLES.read_text(encoding="utf-8"))
        again = json.loads(json.dumps(document))
        again["source"]["sha256"] = "different download, same content"
        again["generated_by"] = "another tool"
        assert extract.same_content(document, again)
        again["points"]["AI"][0]["name"] = "changed"
        assert not extract.same_content(document, again)


class _Served:
    """An outstation listening on a thread of its own, for a command to poll."""

    def __init__(self) -> None:
        simulation = der.build(load.resolve(for_reference_der(), Composition()))
        self._loop = asyncio.new_event_loop()
        self._server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)

    def __enter__(self) -> int:
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._server.start(), self._loop).result(5)
        return self._server.port

    def __exit__(self, *_exc) -> None:
        asyncio.run_coroutine_threadsafe(self._server.stop(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


class TestPoll:
    def test_it_reports_what_a_running_outstation_answered(self, tables, capsys):
        with _Served() as port:
            assert cli.main(["poll", "--port", str(port)]) == 0
        report = capsys.readouterr().out
        assert "answered in" in report and "analog inputs" in report
        assert "Synthetic AI" in report, "names come from the tables on this machine"

    def test_it_works_without_the_tables(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "absent.json"))
        with _Served() as port:
            assert cli.main(["poll", "--port", str(port), "--limit", "3"]) == 0
        lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("  AI")]
        assert len(lines) == 3

    def test_nothing_listening_is_a_failure_with_a_reason(self, capsys):
        assert cli.main(["poll", "--port", "1", "--timeout", "2"]) == 1
        assert "cannot connect" in capsys.readouterr().err


class TestRun:
    def test_a_port_in_use_is_reported(self, tables, capsys):
        with _Served() as port:
            assert cli.main(["run", "--bind", f"127.0.0.1:{port}"]) == 1
        assert "cannot listen" in capsys.readouterr().err


class TestArguments:
    """What the command line refuses before anything is loaded or served."""

    @pytest.mark.parametrize("option", ["--meters", "--der-units", "--inverters", "--batteries"])
    @pytest.mark.parametrize("command", ["run", "points"])
    def test_a_negative_count_is_refused_as_usage(self, command, option, tables, capsys):
        with pytest.raises(SystemExit) as stopped:
            cli.main([command, option, "-1"])
        assert stopped.value.code == 2
        message = capsys.readouterr().err
        assert "cannot be negative" in message
        assert "Traceback" not in message

    @pytest.mark.parametrize("tick", ["0", "-1", "nan", "inf", "soon"])
    def test_a_tick_that_is_no_interval_is_refused_as_usage(self, tick, tables, capsys):
        """Zero or less would spin the run loop; the server is never started."""
        with pytest.raises(SystemExit) as stopped:
            cli.main(["run", "--tick", tick])
        assert stopped.value.code == 2
        assert "--tick" in capsys.readouterr().err

    def test_a_composition_that_refuses_itself_is_reported_not_raised(self, tables, capsys):
        """Past the parser, for a caller that builds the arguments itself."""
        args = cli._parser().parse_args(["points"])
        args.meters = -1
        assert cli._load(args) is None
        assert "composition.meters must be a whole number" in capsys.readouterr().err
