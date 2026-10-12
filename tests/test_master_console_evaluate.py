"""The console's Evaluate tab, loaded in a real browser against the simulated DER.

The tab holds no logic: the checks, their verdicts and the deviations are the
service's, and are tested at the service. What is tested here is the page:
that it lists the checks by set, runs the ones chosen and shows each verdict
and the report, says why a check was not run, shows the deviations as the
service reports them, and offers no run for an outstation with no profile. A
machine with no browser skips these; see ``browser.py``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from dataclasses import dataclass

import pytest
import pytest_asyncio
from browser import Page, open_page
from profile_fixtures import paired_reference_der

from py1815.master.service import HttpServer, Service
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind, PointMap
from py1815.server import OutstationServer


@dataclass
class Console:
    page: Page
    service: Service
    points: PointMap
    port: int

    async def ask(self, op: str, **params):
        answer = await self.service.handle({"op": op, "outstation": "lab", "params": params})
        assert answer["ok"], answer
        return answer["result"]


#: For a test of the tab over a service started to command.
commanding = pytest.mark.parametrize("console", [True], indirect=True)


@pytest_asyncio.fixture
async def console(request):
    """The console in a browser, on its Evaluate tab, with the simulated DER added.

    The outstation is added with nothing sent unasked, so the only traffic is
    what a check sends, and with a short response timeout, so a check that
    expects no answer ends quickly.
    """
    points = load.resolve(paired_reference_der(), Composition())
    simulation = der.build(points)
    outstation = OutstationServer(
        simulation.outstation.session(need_time=False), bind="127.0.0.1:0"
    )
    service = Service(allow_control=getattr(request, "param", False))
    http = HttpServer(service, bind="127.0.0.1:0")
    await outstation.start()
    await http.start()
    try:
        service.set_profile("lab", points)
        added = await service.handle(
            {
                "op": "add",
                "params": {
                    "name": "lab",
                    "host": "127.0.0.1",
                    "port": outstation.port,
                    "response_timeout": 0.3,
                    "manual": True,
                    "confirm": True,
                },
            }
        )
        assert added["ok"], added
        async with open_page() as page:
            await page.goto(http.url)
            await page.wait_for("document.querySelector('#title').textContent === 'lab'")
            await page.click(".tabs [data-tab='evaluate']")
            await page.wait_for(
                "document.querySelectorAll('#evaluate-checks tr[data-check]').length"
            )
            await page.wait_for(
                "document.querySelectorAll('#evaluate-deviations .deviation').length"
            )
            yield Console(page, service, points, outstation.port)
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


def _row(check: str) -> str:
    """Return the expression for a check's row in the table."""
    return f"document.querySelector(\"#evaluate-checks tr[data-check='{check}']\")"


def _switch(deviation: str) -> str:
    """Return the expression for a deviation's switch."""
    return f"document.querySelector(\"#evaluate-deviations input[data-deviation='{deviation}']\")"


async def _run(page: Page, *checks: str) -> None:
    """Choose only the checks named, run them, and wait for the report."""
    await page.click("#evaluate-none")
    for check in checks:
        await page.click(f"#evaluate-checks input[data-check='{check}']")
    assert await page.evaluate("[...evaluation.selected]") == list(checks)
    await page.click("#evaluate-run")
    await page.wait_for("document.querySelector('#evaluate-summary') !== null")


async def _summary(page: Page) -> dict[str, int]:
    """Return the count the report shows for each verdict."""
    return dict(
        await page.evaluate(
            "[...document.querySelectorAll('#evaluate-summary dd')]"
            ".map((count) => [count.dataset.verdict, Number(count.textContent)])"
        )
    )


class TestTheChecks:
    @pytest.mark.asyncio
    async def test_the_checks_are_listed_by_set_in_the_order_the_service_gives(self, console):
        page = console.page
        listed = (await console.ask("checks"))["checks"]
        sets = list(dict.fromkeys(check["set"] for check in listed))

        assert (
            await page.evaluate(
                "[...document.querySelectorAll('#evaluate-checks tbody')].map((b) => b.dataset.set)"
            )
            == sets
        )
        for name in sets:
            shown = await page.evaluate(
                f"[...document.querySelectorAll(\"#evaluate-checks tbody[data-set='{name}']"
                ' tr[data-check]")].map((row) => row.dataset.check)'
            )
            assert shown == [check["id"] for check in listed if check["set"] == name]
        assert await page.text("#evaluate-checks tr[data-check='MON-001'] .check-title") == (
            "Monitoring"
        )
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_a_check_that_writes_and_one_that_deviates_are_marked(self, console):
        page = console.page
        marks = "[...{}.querySelectorAll('.mark')].map((mark) => mark.textContent)"
        assert await page.evaluate(marks.format(_row("MON-001"))) == []
        assert await page.evaluate(marks.format(_row("CONN-001"))) == ["writes"]
        assert await page.evaluate(marks.format(_row("LINK-001"))) == ["deviates"]

    @pytest.mark.asyncio
    async def test_a_set_and_all_or_none_can_be_chosen_at_once(self, console):
        page = console.page
        listed = (await console.ask("checks"))["checks"]
        every = [check["id"] for check in listed]
        deviation = [check["id"] for check in listed if check["set"] == "deviation"]
        assert await page.evaluate("[...evaluation.selected]") == every

        await page.click("#evaluate-none")
        assert await page.evaluate("[...evaluation.selected]") == []
        assert await page.evaluate("document.querySelector('#evaluate-run').disabled")
        assert await page.count("#evaluate-checks input[data-check]:checked") == 0

        await page.click("#evaluate-checks input[data-set='deviation']")
        assert await page.evaluate("[...evaluation.selected]") == deviation
        assert await page.count("#evaluate-checks input[data-check]:checked") == len(deviation)
        assert not await page.evaluate("document.querySelector('#evaluate-run').disabled")

        await page.click("#evaluate-all")
        assert await page.count("#evaluate-checks input[data-check]:checked") == len(every)


class TestRunning:
    @pytest.mark.asyncio
    async def test_a_check_that_passes_is_shown_as_passed_with_the_summary(self, console):
        page = console.page
        await _run(page, "MON-001")

        assert await page.text("#evaluate-checks tr[data-check='MON-001'] .check-verdict") == (
            "passed"
        )
        assert "of the meter's" in await page.evaluate(f"{_row('MON-001')}.cells[4].textContent")
        assert await _summary(page) == {
            "passed": 1,
            "failed": 0,
            "not_applicable": 0,
            "not_run": 0,
        }
        words = await page.evaluate(
            "[...document.querySelectorAll('#evaluate-summary dt')].map((term) => term.textContent)"
        )
        assert words == ["passed", "FAILED", "not applicable", "not run"]
        # Only the check that was chosen has a verdict.
        assert await page.count("#evaluate-checks .check-verdict") == 1
        assert not await page.evaluate("document.querySelector('#evaluate-run').disabled")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_each_check_event_fills_its_row_before_the_answer_comes(self, console):
        """The row is drawn from the event, with no run of this page's under way."""
        page = console.page
        await page.click("#evaluate-none")
        report = await console.ask("evaluate", checks=["OP-001"])
        (result,) = report["results"]
        assert result["verdict"] == "passed"

        await page.wait_for(f"{_row('OP-001')}.querySelector('.check-verdict') !== null")

        assert await page.text("#evaluate-checks tr[data-check='OP-001'] .check-verdict") == (
            "passed"
        )
        # The page asked for no evaluation, so it has no report to show.
        assert await page.count("#evaluate-summary") == 0

    @pytest.mark.asyncio
    async def test_a_check_that_deviates_is_not_run_until_the_switch_allows_it(self, console):
        page = console.page
        await _run(page, "LINK-001")
        await page.wait_for(
            f"{_row('LINK-001')}.querySelector('.check-verdict')?.textContent === 'not run'"
        )
        found = await page.evaluate(f"{_row('LINK-001')}.cells[4].textContent")
        assert "it breaks a protocol rule on purpose, and the run was not allowed to" in found
        assert (await _summary(page))["not_run"] == 1

        await page.click("#evaluate-allow-deviations")
        await page.click("#evaluate-run")

        await page.wait_for(
            f"{_row('LINK-001')}.querySelector('.check-verdict')?.textContent === 'passed'"
        )
        await page.wait_for("document.querySelector('#evaluate-summary') !== null")
        assert await _summary(page) == {
            "passed": 1,
            "failed": 0,
            "not_applicable": 0,
            "not_run": 0,
        }
        # The check turned its deviation off again, so the master is left conformant.
        assert (await console.ask("deviate"))["on"] == []
        assert await page.evaluate("document.querySelector('#deviation-state').hidden")

    @pytest.mark.asyncio
    async def test_a_check_that_writes_is_not_run_when_commanding_is_off(self, console):
        page = console.page
        assert "will be reported as not run" in await page.text("#evaluate-read-only")
        await _run(page, "CONN-001")

        await page.wait_for(
            f"{_row('CONN-001')}.querySelector('.check-verdict')?.textContent === 'not run'"
        )
        found = await page.evaluate(f"{_row('CONN-001')}.cells[4].textContent")
        assert "it writes to the outstation, and the run was not allowed to" in found
        assert (await _summary(page))["not_run"] == 1
        assert "Not allowed: commanding is off" in await page.text("#evaluate-report")

    @pytest.mark.asyncio
    @commanding
    async def test_a_check_that_writes_is_run_when_commanding_is_on(self, console):
        page = console.page
        assert await page.count("#evaluate-read-only") == 0
        assert "Commanding is on" in await page.text("#evaluate-commanding")
        await _run(page, "CONN-001")

        await page.wait_for(
            f"{_row('CONN-001')}.querySelector('.check-verdict')?.textContent === 'passed'"
        )
        assert (await _summary(page))["passed"] == 1

    @pytest.mark.asyncio
    @commanding
    async def test_a_function_checks_row_takes_the_title_its_result_gives(self, console):
        """The list names the function by its enable output, and the result by what it found."""
        page = console.page
        title = "#evaluate-checks tr[data-check='APL-001'] .check-title"
        listed = {check["id"]: check["title"] for check in (await console.ask("checks"))["checks"]}
        assert await page.text(title) == listed["APL-001"]
        await _run(page, "APL-001")

        await page.wait_for(
            f"{_row('APL-001')}.querySelector('.check-verdict')?.textContent === 'passed'"
        )
        found = await page.evaluate("evaluation.runs.get('lab').report.results[0].title")
        assert found != listed["APL-001"] and found.endswith(": supported")
        assert await page.text(title) == found

    @pytest.mark.asyncio
    async def test_a_failed_check_shows_why_and_leads_to_its_frames(self, console):
        page = console.page
        # The service is given tables whose range the meter's first point is outside.
        meter = (Kind.AI, der.AI_METER_FIRST)
        limited = dataclasses.replace(
            console.points.points[meter], minimum=10**9, maximum=10**9 + 1
        )
        console.service.set_profile(
            "lab",
            dataclasses.replace(console.points, points={**console.points.points, meter: limited}),
        )
        await _run(page, "MON-001")

        await page.wait_for(
            f"{_row('MON-001')}.querySelector('.check-verdict')?.textContent === 'FAILED'"
        )
        assert "outside the range the tables give" in await page.text(
            "#evaluate-checks tr[data-check='MON-001'] .check-detail.failed"
        )
        assert (await _summary(page))["failed"] == 1
        first, last = await page.evaluate("evaluation.runs.get('lab').report.results[0].frames")
        assert await page.text("#evaluate-checks button[data-frames='MON-001']") == (
            f"frames {first} to {last}"
        )
        # Frames that crossed the wire after the check ended are not the check's.
        await console.ask("scan", kind="class0")
        assert console.service.master["lab"].trace.last_id > last

        await page.click("#evaluate-checks button[data-frames='MON-001']")

        await page.wait_for("state.tab === 'traffic' && state.range !== null")
        await page.wait_for("document.querySelectorAll('#traffic-table tbody tr').length")
        assert await page.text("#traffic-range-text") == f"Frames {first} to {last}, of MON-001"
        assert await page.evaluate("state.range.frames.map((frame) => frame.id)") == list(
            range(first, last + 1)
        )
        assert await page.count("#traffic-table tbody tr") == min(300, last - first + 1)
        assert await page.evaluate("state.frame.id") in range(first, last + 1)

        await page.click("#traffic-range-clear")
        assert await page.evaluate("state.range") is None
        assert await page.evaluate(
            "getComputedStyle(document.querySelector('#traffic-range')).display"
        ) == ("none")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_the_report_is_offered_as_a_json_file(self, console):
        page = console.page
        await _run(page, "MON-001", "OP-001")
        # Keep the file the page offers instead of letting the browser save it.
        await page.evaluate(
            "window.saved = null;"
            "URL.createObjectURL = (blob) => { window.saved = blob; return 'blob:kept'; };"
            "HTMLAnchorElement.prototype.click = function () { window.savedAs = this.download; };"
        )

        await page.click("#evaluate-save")
        await page.wait_for("window.saved !== null")

        assert await page.evaluate("window.saved.type") == "application/json"
        report = json.loads(await page.evaluate("window.saved.text()"))
        assert report["tool"] == "py1815-master evaluate" and report["outstation"] == "lab"
        assert [result["id"] for result in report["results"]] == ["MON-001", "OP-001"]
        assert report["summary"]["passed"] == 2
        name = await page.evaluate("window.savedAs")
        assert name.startswith("lab-evaluation-") and name.endswith(".json")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_an_evaluation_the_service_refuses_is_shown_as_an_error(self, console):
        """One evaluation runs against an outstation at a time, and a second is refused."""
        page = console.page
        # An evaluation asked for by another client, long enough to be under way.
        other = asyncio.ensure_future(
            console.ask("evaluate", checks=["deviation"], allow_deviations=True)
        )
        try:
            await page.wait_for(f"{_row('LINK-001')}.querySelector('.check-verdict') !== null")
            assert not other.done(), "the other evaluation is still running"
            await page.click("#evaluate-none")
            await page.click("#evaluate-checks input[data-check='MON-001']")

            await page.click("#evaluate-run")

            await page.wait_for("document.querySelector('#evaluate-error') !== null")
            assert await page.text("#evaluate-error") == "an evaluation of lab is already running"
            assert await page.count("#evaluate-summary") == 0
            assert not await page.evaluate("document.querySelector('#evaluate-run').disabled")
            await page.click(".tabs [data-tab='log']")
            assert "lab: evaluation failed: an evaluation of lab is already running" in (
                await page.text("#log")
            )
        finally:
            report = await other
        assert report["summary"]["failed"] == 0, report


class TestDeviations:
    @pytest.mark.asyncio
    async def test_every_deviation_the_service_names_has_a_switch_and_a_description(self, console):
        page = console.page
        named = list((await console.ask("deviate"))["deviations"])
        shown = await page.evaluate(
            "[...document.querySelectorAll('#evaluate-deviations .deviation')]"
            ".map((row) => [row.dataset.deviation, row.querySelector('.hint').textContent])"
        )
        assert [name for name, _ in shown] == named
        assert all(description for _, description in shown), shown
        assert await page.count("#evaluate-deviations input[role='switch']:checked") == 0
        assert await page.evaluate("document.querySelector('#deviation-state').hidden")
        assert await page.evaluate("document.querySelector('#deviations-clear').disabled")

    @pytest.mark.asyncio
    async def test_a_switch_turns_a_deviation_on_and_turn_all_off_clears_it(self, console):
        page = console.page
        await page.click("#evaluate-deviations input[data-deviation='corrupt_header_crc']")

        await page.wait_for(
            "document.querySelector('#deviations-on').textContent.includes('corrupt_header_crc')"
        )
        assert (await console.ask("deviate"))["on"] == ["corrupt_header_crc"]
        assert await page.evaluate(f"{_switch('corrupt_header_crc')}.checked")
        assert await page.count("#evaluate-deviations input[role='switch']:checked") == 1
        # Said beside the outstation's name too, where every tab shows it.
        assert not await page.evaluate("document.querySelector('#deviation-state').hidden")
        assert await page.text("#deviation-state") == "Deviations on"

        await page.click("#deviations-clear")

        await page.wait_for(
            "document.querySelector('#deviations-on').textContent.startsWith('None is on')"
        )
        assert (await console.ask("deviate"))["on"] == []
        assert await page.count("#evaluate-deviations input[role='switch']:checked") == 0
        assert await page.evaluate("document.querySelector('#deviation-state').hidden")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_a_deviation_turned_on_elsewhere_is_shown_when_the_tab_is_opened(self, console):
        """The switches show what the service says, and not what this page last did."""
        page = console.page
        await console.ask("deviate", set={"truncate": True})
        await page.click(".tabs [data-tab='log']")
        assert not await page.evaluate(f"{_switch('truncate')}.checked")

        await page.click(".tabs [data-tab='evaluate']")

        await page.wait_for(f"{_switch('truncate')}.checked")
        assert "truncate" in await page.text("#deviations-on")

    @pytest.mark.asyncio
    async def test_a_change_the_service_refuses_leaves_the_switch_as_the_service_has_it(
        self, console
    ):
        page = console.page
        # A switch for a name the service does not know, as a newer page might
        # have, made and clicked in one step so nothing redraws it in between.
        await page.evaluate(
            "(() => { evaluation.deviations.deviations.not_a_deviation = false;"
            " renderDeviations(); document.querySelector("
            "\"#evaluate-deviations input[data-deviation='not_a_deviation']\").click(); })()"
        )

        await page.wait_for("document.querySelector('#evaluate-deviations .error') !== null")
        assert "not_a_deviation is not a deviation" in await page.text(
            "#evaluate-deviations .error"
        )
        assert await page.count("#evaluate-deviations input[data-deviation='not_a_deviation']") == 0
        assert (await console.ask("deviate"))["on"] == []


class TestWithNoProfile:
    @pytest.mark.asyncio
    async def test_the_tab_says_why_and_offers_no_run(self, console):
        page = console.page
        added = await console.service.handle(
            {
                "op": "add",
                "params": {"name": "plain", "host": "127.0.0.1", "port": 1, "connect": False},
            }
        )
        assert added["ok"]
        await page.wait_for("document.querySelectorAll('#outstations li').length === 2")
        await page.evaluate("select('plain')")

        await page.wait_for("document.querySelector('#evaluate-unavailable') !== null")
        refused = await console.service.handle({"op": "evaluate", "outstation": "plain"})
        assert await page.text("#evaluate-unavailable") == refused["error"]["message"]
        assert "plain was given no profile" in await page.text("#evaluate-unavailable")
        assert await page.count("#evaluate-run") == 0
        assert await page.count("#evaluate-checks") == 0
        # The deviations need no profile, and are still offered.
        assert await page.count("#evaluate-deviations input[role='switch']") > 0
        assert page.errors == []


class TestLoading:
    @pytest.mark.asyncio
    async def test_it_asks_the_outside_world_for_nothing(self, console):
        own = (await console.page.evaluate("location.origin")).rstrip("/")
        assert console.page.requests, "the page did load something"
        assert [url for url in console.page.requests if not url.startswith(own)] == []
