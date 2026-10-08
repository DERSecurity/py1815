"""``py1815-master poll`` and ``py1815-der poll``: one integrity poll, by the master."""

from __future__ import annotations

import pytest
from test_master_association import ANALOG, BINARY, _built, _from_outstation
from test_profile_cli import _Served, tables  # noqa: F401  (a fixture)

from py1815.application import FunctionCode
from py1815.master import cli as master_cli
from py1815.master import poll
from py1815.master import requests as rq
from py1815.profile import cli as der_cli
from py1815.profile import load


def _poll_of(response: str) -> poll.Poll:
    association, _ = _built()
    association.request(FunctionCode.READ, rq.scan("integrity"))
    association.receive(_from_outstation(response))
    return poll.Poll(association.take())


class TestTheReport:
    def test_it_counts_by_group_and_lists_the_analog_inputs(self):
        report = poll.report(
            _poll_of(f"C0 81 80 00 {BINARY} {ANALOG}"), "lab:20000", None, limit=12, every=False
        )
        assert report == [
            "lab:20000 answered in 1 fragment(s): 1 binary inputs, 0 counters, "
            "0 frozen counters, 1 analog inputs",
            "  0 event(s); indications 0x80 0x00",
            "  AI0                 300",
        ]

    def test_what_could_not_be_read_is_said(self):
        report = poll.report(
            _poll_of(f"C0 81 00 00 {ANALOG} 63 01 00 00 00"), "lab:1", None, limit=1, every=False
        )
        assert report[-2].startswith("  not read past this point: ")
        assert report[-1] == "  AI0                 300"


class TestTheCommands:
    @pytest.mark.usefixtures("tables")
    def test_both_commands_print_the_same_report(self, capsys):
        with _Served() as port:
            assert master_cli.main(["poll", "--port", str(port), "--limit", "5"]) == 0
            by_master = capsys.readouterr().out.splitlines()
            assert der_cli.main(["poll", "--port", str(port), "--limit", "5"]) == 0
            by_der = capsys.readouterr().out.splitlines()
        # The event count differs: the first poll confirmed the events it read.
        assert by_master[0] == by_der[0] and by_master[2:] == by_der[2:]
        assert len(by_master) == 7 and "Synthetic AI" in by_master[-1]

    @pytest.mark.parametrize("main", [master_cli.main, der_cli.main])
    def test_an_outstation_that_does_not_answer_is_a_failure_with_a_reason(self, main, capsys):
        with _Served() as port:
            status = main(
                ["poll", "--port", str(port), "--outstation-address", "9", "--timeout", "0.3"]
            )
        assert status == 1
        assert "no answer from" in capsys.readouterr().err

    @pytest.mark.parametrize("main", [master_cli.main, der_cli.main])
    def test_both_commands_take_a_count_of_retries(self, main, capsys):
        with _Served() as port:
            status = main(
                [
                    "poll",
                    "--port",
                    str(port),
                    "--outstation-address",
                    "9",
                    "--timeout",
                    "0.2",
                    "--read-retries",
                    "2",
                ]
            )
        assert status == 1 and "no answer" in capsys.readouterr().err

    def test_a_negative_count_is_refused_as_usage(self, capsys):
        with pytest.raises(SystemExit) as stopped:
            master_cli.main(["poll", "--read-retries", "-1"])
        assert stopped.value.code == 2
        assert "cannot be negative" in capsys.readouterr().err

    def test_addresses_the_master_refuses_are_refused_as_usage(self, capsys):
        status = master_cli.main(
            ["poll", "--port", "1", "--outstation-address", "5", "--master-address", "5"]
        )
        assert status == 2 and "both 5" in capsys.readouterr().err

    def test_without_the_tables_the_inputs_are_listed_unnamed(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv(load.TABLES_VARIABLE, str(tmp_path / "absent.json"))
        with _Served() as port:
            assert master_cli.main(["poll", "--port", str(port), "--limit", "2"]) == 0
        lines = capsys.readouterr().out.splitlines()
        assert [line for line in lines if line.startswith("  AI")] == lines[2:]
        assert len(lines) == 4
