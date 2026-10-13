"""The record of the dnp3c conformance run, and what is written from it.

`interop/dnp3c/expected.json` says how each procedure of the harness ends
against this library's outstation. The conformance job compares every run
with it, using `interop/dnp3c/check_outcomes.py`. The harness needs Java and
runs only in that job, so these tests cover what can be checked without it:

- that the comparison catches each way a run can differ from the record,
  shown with a run made up to differ in that way;
- that the record agrees with the files beside it;
- that the documentation carries the record's tables as the record has them.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from typing import Any

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_HERE = _ROOT / "interop" / "dnp3c"


def _load() -> Any:
    """Load the comparison, which is a script and not a package."""
    spec = importlib.util.spec_from_file_location("check_outcomes", _HERE / "check_outcomes.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check = _load()

#: A small record with one procedure of each kind.
RECORD: dict[str, Any] = {
    "tool": "dnp3c",
    "version": "1.2.3",
    "options": {"supports.widgets": "The outstation has no widgets."},
    "procedures": {
        "8.1.2": {"outcome": "passed"},
        "8.2.1": {"outcome": "skipped", "option": "supports.widgets", "needs": "true"},
        "8.2.2": {"outcome": "skipped", "option": "supports.gadgets", "needs": "false"},
        "8.3.2": {"outcome": "not implemented"},
        "8.10.2": {"outcome": "failed", "reason": "The outstation answers late."},
    },
}

_RESULT = {"passed": "pass", "skipped": "skip", "not implemented": "skip", "failed": "fail"}


def _detail(procedure: str, entry: dict[str, str]) -> str:
    """Word an outcome the way the harness does."""
    if entry["outcome"] == "skipped":
        return f"disabled because {entry['option']} != {entry['needs']}"
    if entry["outcome"] == "not implemented":
        return f"incomplete procedure: {procedure} - Not implemented!"
    return "Expected a response" if entry["outcome"] == "failed" else ""


def write_run(directory: pathlib.Path, procedures: dict[str, dict[str, str]]) -> pathlib.Path:
    """Write the files a run of these procedures leaves, and return their directory."""
    summary = {}
    for procedure, entry in procedures.items():
        folder = directory / procedure
        folder.mkdir(parents=True)
        result = _RESULT[entry["outcome"]]
        (folder / "results.properties").write_text(
            f"#test result\nresult={result}\n", encoding="utf-8"
        )
        outcome = "skipped" if entry["outcome"] == "not implemented" else entry["outcome"]
        summary[procedure] = {"outcome": outcome, "detail": _detail(procedure, entry)}
    (directory / "outcomes.json").write_text(json.dumps({"procedures": summary}), encoding="utf-8")
    return directory


def problems(
    tmp_path: pathlib.Path,
    procedures: dict[str, dict[str, str]],
    *,
    record: dict[str, Any] = RECORD,
    version: str = "1.2.3",
    off: tuple[str, ...] = ("supports.widgets",),
) -> list[str]:
    """Compare a made-up run with a record, and return what differs."""
    run = check.read_run(write_run(tmp_path / "results", procedures))
    found: list[str] = check.compare(record, run, version=version, off=list(off))
    return found


def changed(procedure: str, **entry: str) -> dict[str, dict[str, str]]:
    """The record's procedures with one of them ending another way."""
    return {**RECORD["procedures"], procedure: entry}


class TestTheComparison:
    def test_a_run_that_is_the_one_on_record_has_nothing_to_report(self, tmp_path):
        assert problems(tmp_path, RECORD["procedures"]) == []

    def test_a_procedure_that_starts_to_fail_is_reported(self, tmp_path):
        found = problems(tmp_path, changed("8.1.2", outcome="failed"))
        assert found == ["8.1.2 is on record as passed and ended failed (Expected a response)"]

    def test_a_procedure_that_starts_to_pass_is_reported(self, tmp_path):
        found = problems(tmp_path, changed("8.10.2", outcome="passed"))
        assert found == ["8.10.2 is on record as failed and ended passed"]

    def test_a_procedure_that_stops_running_is_reported(self, tmp_path):
        ran = {k: v for k, v in RECORD["procedures"].items() if k != "8.2.1"}
        assert problems(tmp_path, ran) == ["8.2.1 is on record as skipped and did not run"]

    def test_a_procedure_that_is_not_on_record_is_reported(self, tmp_path):
        ran = {**RECORD["procedures"], "8.4.2": {"outcome": "passed"}}
        assert problems(tmp_path, ran) == ["8.4.2 ran, ending passed, and is not on record"]

    def test_a_procedure_skipped_for_another_option_is_reported(self, tmp_path):
        ran = changed("8.2.1", outcome="skipped", option="supports.sprockets", needs="true")
        (found,) = problems(tmp_path, ran)
        assert "8.2.1 is on record as skipped for supports.widgets" in found
        assert "supports.sprockets" in found

    def test_a_procedure_the_harness_stops_implementing_is_not_a_plain_skip(self, tmp_path):
        ran = changed("8.2.1", outcome="not implemented")
        assert problems(tmp_path, ran) == [
            "8.2.1 is on record as skipped and ended not implemented "
            "(incomplete procedure: 8.2.1 - Not implemented!)"
        ]

    def test_a_failure_on_record_needs_a_reason(self, tmp_path):
        record = json.loads(json.dumps(RECORD))
        record["procedures"]["8.10.2"]["reason"] = " "
        found = problems(tmp_path, RECORD["procedures"], record=record)
        assert found == ["8.10.2 is on record as failed with no reason"]

    def test_an_option_that_is_off_needs_a_reason(self, tmp_path):
        found = problems(
            tmp_path, RECORD["procedures"], off=("supports.widgets", "supports.levers")
        )
        assert found == ["supports.levers is off and the record gives no reason"]

    def test_a_reason_for_an_option_that_is_not_off_is_reported(self, tmp_path):
        record = json.loads(json.dumps(RECORD))
        record["options"]["supports.levers"] = "There are no levers."
        (found,) = problems(tmp_path, RECORD["procedures"], record=record)
        assert found.startswith("the record gives a reason for supports.levers")

    def test_a_record_of_another_version_of_the_harness_is_reported(self, tmp_path):
        found = problems(tmp_path, RECORD["procedures"], version="1.2.4")
        assert found == ["the record is of dnp3c 1.2.3 and pom.xml pins 1.2.4"]

    def test_procedures_are_ordered_by_number_and_not_as_text(self, tmp_path):
        run = check.read_run(write_run(tmp_path / "results", RECORD["procedures"]))
        assert list(run) == ["8.1.2", "8.2.1", "8.2.2", "8.3.2", "8.10.2"]


class TestWhatARunLeft:
    def test_a_result_file_that_disagrees_with_the_summary_is_refused(self, tmp_path):
        results = write_run(tmp_path / "results", RECORD["procedures"])
        (results / "8.1.2" / "results.properties").write_text("result=fail\n", encoding="utf-8")
        with pytest.raises(SystemExit, match=r"8\.1\.2 is failed in its result file"):
            check.read_run(results)

    def test_a_procedure_the_harness_could_not_run_is_refused(self, tmp_path):
        results = write_run(tmp_path / "results", RECORD["procedures"])
        summary = json.loads((results / "outcomes.json").read_text(encoding="utf-8"))
        summary["procedures"]["8.5.1"] = {"outcome": "error", "detail": "the device did not start"}
        (results / "outcomes.json").write_text(json.dumps(summary), encoding="utf-8")
        with pytest.raises(SystemExit, match=r"left no result for: 8\.5\.1"):
            check.read_run(results)

    def test_a_run_that_did_not_finish_is_refused(self, tmp_path):
        results = write_run(tmp_path / "results", RECORD["procedures"])
        (results / "outcomes.json").unlink()
        with pytest.raises(SystemExit, match="the run did not finish"):
            check.read_run(results)

    def test_a_skip_that_names_no_option_is_refused(self, tmp_path):
        results = write_run(tmp_path / "results", RECORD["procedures"])
        summary = json.loads((results / "outcomes.json").read_text(encoding="utf-8"))
        summary["procedures"]["8.2.1"]["detail"] = "skipped by hand"
        (results / "outcomes.json").write_text(json.dumps(summary), encoding="utf-8")
        with pytest.raises(SystemExit, match=r"8\.2\.1 was skipped for no option"):
            check.read_run(results)


class TestPuttingARunOnRecord:
    def _files(self, tmp_path: pathlib.Path) -> list[str]:
        (tmp_path / "pom.xml").write_text(
            "<project><properties><dnp3c.version>1.2.3</dnp3c.version></properties></project>",
            encoding="utf-8",
        )
        (tmp_path / "device.ini").write_text(
            "# a comment\nsupports.widgets = false\nsupports.gadgets = true\nlink.source = 1\n",
            encoding="utf-8",
        )
        return [
            "--results",
            str(tmp_path / "results"),
            "--expected",
            str(tmp_path / "expected.json"),
            "--pom",
            str(tmp_path / "pom.xml"),
            "--device",
            str(tmp_path / "device.ini"),
        ]

    def test_the_run_on_record_passes_the_comparison(self, tmp_path, capsys):
        arguments = self._files(tmp_path)
        write_run(tmp_path / "results", RECORD["procedures"])
        (tmp_path / "expected.json").write_text(json.dumps(RECORD), encoding="utf-8")
        assert check.main(arguments) == 0
        assert "the run is the one on record" in capsys.readouterr().out

    def test_a_run_that_differs_fails_and_says_how(self, tmp_path, capsys):
        arguments = self._files(tmp_path)
        write_run(tmp_path / "results", changed("8.1.2", outcome="failed"))
        (tmp_path / "expected.json").write_text(json.dumps(RECORD), encoding="utf-8")
        assert check.main(arguments) == 1
        assert "8.1.2 is on record as passed and ended failed" in capsys.readouterr().out

    def test_writing_keeps_the_reasons_given_and_leaves_a_new_one_empty(self, tmp_path):
        arguments = self._files(tmp_path)
        write_run(tmp_path / "results", changed("8.1.2", outcome="failed"))
        (tmp_path / "expected.json").write_text(json.dumps(RECORD), encoding="utf-8")
        # The new failure has no reason yet, so the record it writes does not pass.
        assert check.main([*arguments, "--write"]) == 1
        written = json.loads((tmp_path / "expected.json").read_text(encoding="utf-8"))
        assert written["version"] == "1.2.3"
        assert written["options"] == RECORD["options"]
        assert written["procedures"]["8.10.2"] == RECORD["procedures"]["8.10.2"]
        assert written["procedures"]["8.1.2"] == {"outcome": "failed", "reason": ""}
        assert written["procedures"]["8.2.2"] == RECORD["procedures"]["8.2.2"]


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    """The record in the repository."""
    loaded: dict[str, Any] = json.loads((_HERE / "expected.json").read_text(encoding="utf-8"))
    return loaded


class TestTheRecordInTheRepository:
    def test_it_agrees_with_the_files_beside_it(self, record, tmp_path):
        """A run that ends as the record says has nothing to report against it."""
        run = check.read_run(write_run(tmp_path / "results", record["procedures"]))
        assert (
            check.compare(
                record,
                run,
                version=check.pinned_version(_HERE / "pom.xml"),
                off=check.options_off(_HERE / "device.ini"),
            )
            == []
        )

    def test_every_option_that_is_off_is_explained_in_the_readme(self):
        readme = (_HERE / "README.md").read_text(encoding="utf-8")
        missing = [
            name for name in check.options_off(_HERE / "device.ini") if f"`{name}`" not in readme
        ]
        assert not missing, f"interop/dnp3c/README.md does not say why these are off: {missing}"

    def test_every_section_has_a_description(self, record):
        sections = {".".join(procedure.split(".")[:2]) for procedure in record["procedures"]}
        assert sections <= set(check.SECTIONS)

    def test_no_procedure_is_skipped_for_an_option_the_device_file_has_on(self, record):
        device = check.read_properties(_HERE / "device.ini")
        for procedure, entry in record["procedures"].items():
            if entry["outcome"] == "skipped":
                # A procedure that needs a feature is skipped because the option is off, and
                # one for a device without the feature because it is on.
                expected = "false" if entry["needs"] == "true" else "true"
                assert device[entry["option"]] == expected, procedure


class TestTheSummaryPage:
    def test_it_carries_each_table_as_the_record_has_it(self, record):
        page = (_ROOT / "docs" / "conformance.md").read_text(encoding="utf-8")
        for name, table in check.markdown(record).items():
            block = f"<!-- record: {name} -->\n{table}\n<!-- end -->"
            assert block in page, (
                f"docs/conformance.md does not carry the '{name}' table as the record has it; "
                "python interop/dnp3c/check_outcomes.py --markdown prints it"
            )

    def test_it_names_the_version_the_record_is_of(self, record):
        page = (_ROOT / "docs" / "conformance.md").read_text(encoding="utf-8")
        assert f"version {record['version']}" in page

    def test_a_run_of_three_or_more_procedures_is_written_as_a_range(self):
        listed = check.markdown(
            {
                "options": {},
                "procedures": {f"8.2.{n}": {"outcome": "passed"} for n in (1, 2, 3, 5, 6, 10)},
            }
        )["sections"]
        assert "| 8.2.1 to 8.2.3, 8.2.5, 8.2.6, 8.2.10 |" in listed
