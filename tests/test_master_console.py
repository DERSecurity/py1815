"""The web console, loaded in a real browser against a simulated DER.

The console holds no logic of its own, so what it does is tested at the
service. What is tested here is the page: that it loads, shows what the
service reports, does what its controls say, and stays still while it is read.
A machine with no browser skips these; see ``browser.py``.
"""

from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import dataclass

import pytest
import pytest_asyncio
from browser import Page, open_page
from profile_fixtures import for_reference_der

from py1815.master.service import HttpServer, Service
from py1815.profile import der, load
from py1815.profile.model import Composition, Kind
from py1815.server import OutstationServer

WIDTHS = (
    "JSON.stringify([...document.querySelectorAll('#points-table thead th')]"
    ".map(th => Math.round(th.getBoundingClientRect().width)))"
)


#: The analog input the fixture renames, and the name it is given.
ENUMERATED = der.AI_METER_FIRST + 4
ENUMERATED_NAME = "Operating Mode. Enumeration: <0> Off <1> Following the grid <11-255> Reserved"


@dataclass
class Console:
    page: Page
    service: Service
    simulation: der.Simulation
    http: HttpServer
    outstation: OutstationServer

    async def tab(self, name: str) -> None:
        await self.page.click(f".tabs [data-tab='{name}']")

    async def point_type(self, kind: str) -> None:
        await self.page.evaluate(f"state.pointType = '{kind}'; renderPoints()")

    def served(self, kind: Kind) -> int:
        return len(self.simulation.outstation.served(kind))


#: For a test of the console over a service started to command, as
#: ``--allow-control`` starts it. Every other test has one that only reads.
commanding = pytest.mark.parametrize("console", [True], indirect=True)


@pytest_asyncio.fixture
async def console(request):
    """The console in a browser, with one simulated DER added and connected.

    Its integrity poll is repeated and its output status is deliberately not,
    so the outputs are points of the profile the outstation has not reported.
    """
    point_map = load.resolve(for_reference_der(), Composition())
    # One point named the way the profile names an enumeration.
    enumerated = point_map.point(Kind.AI, ENUMERATED)
    point_map = dataclasses.replace(
        point_map,
        points={
            **point_map.points,
            enumerated.address: dataclasses.replace(enumerated, name=ENUMERATED_NAME),
        },
    )
    simulation = der.build(point_map)
    outstation = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    service = Service(allow_control=getattr(request, "param", False))
    http = HttpServer(service, bind="127.0.0.1:0")
    await outstation.start()
    await http.start()
    try:
        service.set_profile("lab", point_map)
        added = await service.handle(
            {
                "op": "add",
                "params": {
                    "name": "lab",
                    "host": "127.0.0.1",
                    "port": outstation.port,
                    "integrity_interval": 30,
                    "event_interval": 0.4,
                    "output_interval": None,
                },
            }
        )
        assert added["ok"], added
        async with open_page() as page:
            await page.goto(http.url)
            await page.wait_for("document.querySelector('#title').textContent === 'lab'")
            await page.wait_for("(state.points.ai || new Map()).size > 0")
            yield Console(page, service, simulation, http, outstation)
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


class TestLoading:
    @pytest.mark.asyncio
    async def test_it_shows_the_outstation_it_was_given_as_connected(self, console):
        page = console.page
        assert await page.evaluate("document.title") == "Satori DNP3 Master"
        assert await page.wait_for(
            "document.querySelector('#service-state').classList.contains('good')"
        )
        assert await page.text("#outstations .name") == "lab"
        assert await page.count("#outstations .lamp.on") == 1
        assert await page.text("#title-state") == "Connected"
        facts = await page.text("#overview-connection")
        assert f"127.0.0.1:{console.outstation.port}" in facts and "1024" in facts
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_it_asks_the_outside_world_for_nothing(self, console):
        """No font, script or style from anywhere but the server that served the page."""
        page = console.page
        await console.tab("points")
        await console.tab("traffic")
        own = console.http.url.rstrip("/")
        assert page.requests, "the page did load something"
        assert [url for url in page.requests if not url.startswith(own)] == []

    @pytest.mark.asyncio
    async def test_the_indications_of_the_last_response_are_lit(self, console):
        page = console.page
        await page.wait_for("document.querySelectorAll('#indications .indication.set').length")
        lit = await page.evaluate(
            "[...document.querySelectorAll('#indications .indication.set')]"
            ".map(lamp => lamp.textContent.trim())"
        )
        assert "IIN1.7 DEVICE_RESTART" in lit and "IIN1.4 NEED_TIME" in lit
        assert await page.count("#indications .indication") == 14


async def _tasks_card(page) -> str:
    """Return the Overview's task card once it has been drawn."""
    await page.wait_for(
        "document.querySelector('#overview-tasks').textContent.includes('Lost connection')"
    )
    return await page.text("#overview-tasks")


class TestAutomaticTasks:
    @pytest.mark.asyncio
    async def test_overview_lists_the_enabled_tasks(self, console):
        page = console.page
        card = await _tasks_card(page)
        assert "Stops unsolicited reporting, reads everything" in card
        assert "Fetched when a response says so" in card
        assert "Made again, trying every 5 s" in card and "Not asked for" in card
        # A service that only reads leaves the two writes alone.
        assert card.count("Left alone") == 2

    @pytest.mark.asyncio
    @commanding
    async def test_commanding_console_also_runs_the_two_writing_tasks(self, console):
        card = await _tasks_card(console.page)
        assert "Cleared when seen" in card and "Set when the outstation asks" in card
        assert "Left alone" not in card

    @pytest.mark.asyncio
    async def test_log_records_each_task_that_runs(self, console):
        page = console.page
        await console.service.handle({"op": "disconnect", "outstation": "lab"})
        await console.service.handle({"op": "connect", "outstation": "lab"})
        await console.service.handle({"op": "idle", "outstation": "lab"})
        await console.tab("log")
        # Wait for the last of the startup requests, not the first.
        await page.wait_for(
            "document.querySelector('#log').textContent.includes('read everything, unasked')"
        )
        log = await page.text("#log")
        assert "lab: stopped unsolicited reporting, on connecting, unasked" in log
        assert "lab: read everything, unasked" in log

    @pytest.mark.asyncio
    async def test_add_form_sets_manual_and_unsolicited(self, console):
        page = console.page
        port = console.outstation.port
        for name, fill in (
            ("by-hand", "form.elements.manual.checked = true;"),
            ("reporting", "form.elements.unsolicited.value = '1, 3';"),
        ):
            await page.evaluate(
                "(() => { const form = document.querySelector('#add-form'); form.reset();"
                f" form.elements.name.value = '{name}'; form.elements.host.value = '127.0.0.1';"
                f" form.elements.port.value = '{port}'; {fill} form.requestSubmit(); }})()"
            )
            await page.wait_for(f"document.querySelector('#title').textContent === '{name}'")
        status = await console.service.handle({"op": "status"})
        added = {each["name"]: each for each in status["result"]["outstations"]}
        assert not any(added["by-hand"]["tasks"].values())
        assert added["reporting"]["tasks"]["enable_unsolicited"] == [1, 3]
        assert added["reporting"]["tasks"]["startup"]
        # The title changes before the Overview is redrawn, so wait for the card itself.
        await page.wait_for(
            "document.querySelector('#overview-tasks').textContent"
            ".includes('Turned on for class 1, 3')"
        )


class TestThePointsTable:
    @pytest.mark.asyncio
    async def test_it_lists_what_the_outstation_reported_by_name(self, console):
        page = console.page
        await console.tab("points")
        await page.wait_for("document.querySelectorAll('#points-table tbody tr').length")

        assert await page.count("#points-table tbody tr") == console.served(Kind.AI)
        power = der.AI_METER_FIRST + 4
        cells = await page.evaluate(
            "[...[...document.querySelectorAll('#points-table tbody tr')]"
            f".find(row => row.cells[0].textContent === '{power}').cells]"
            ".map(cell => cell.textContent.trim())"
        )
        assert cells[1].startswith("Operating Mode")
        assert cells[2] == str(round(console.simulation.der.watts))
        other = await page.evaluate(
            "[...document.querySelector('#points-table tbody tr').cells].map(c => c.textContent)"
        )
        first = console.simulation.outstation.served(Kind.AI)[0]
        assert other[0] == str(first.index) and other[1] == first.name
        assert cells[3] == "ONLINE" and cells[6] == "Static"

        await console.point_type("bi")
        assert await page.count("#points-table tbody tr") == console.served(Kind.BI)
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_it_holds_still_while_values_and_ages_move(self, console):
        """Columns keep their widths, and a row that did not change is not redrawn."""
        page = console.page
        await console.tab("points")
        await page.wait_for("document.querySelectorAll('#points-table tbody tr').length")
        await page.evaluate(
            "document.querySelector('#points-table tbody tr').dataset.mark = 'kept'"
        )
        before = await page.evaluate(WIDTHS)

        seen = set()
        for _ in range(6):
            console.simulation.advance(2.0)
            await asyncio.sleep(0.5)
            seen.add(await page.evaluate(WIDTHS))

        assert seen == {before}
        assert await page.evaluate(
            "document.querySelector('#points-table tbody tr').dataset.mark"
        ) == ("kept")
        ages = await page.evaluate(
            "[...document.querySelectorAll('#points-table tbody td.age')].map(c => c.textContent)"
        )
        assert any(age != "now" for age in ages), "the ages did move on"

    @pytest.mark.asyncio
    async def test_a_longer_value_or_age_does_not_widen_its_column(self, console):
        """What moved the table was a cell gaining a digit, so a cell is made to gain several."""
        page = console.page
        await console.tab("points")
        await page.wait_for("document.querySelectorAll('#points-table tbody tr').length")
        before = await page.evaluate(WIDTHS)

        await page.evaluate(
            "(() => { const row = document.querySelector('#points-table tbody tr');"
            " row.querySelector('td.age').textContent = '1234567890123 s';"
            " row.querySelector('td.value').textContent = '-123456789012345678901234567890'; })()"
        )

        assert await page.evaluate(WIDTHS) == before

    @pytest.mark.asyncio
    async def test_only_a_value_that_changed_is_marked(self, console):
        """A poll that reports the same value again marks nothing."""
        page = console.page
        await console.tab("points")
        await page.wait_for("document.querySelectorAll('#points-table tbody tr').length")
        total = await page.count("#points-table tbody tr")

        console.simulation.advance(5.0)
        await page.wait_for("document.querySelectorAll('#points-table tbody tr.fresh').length")
        assert 0 < await page.count("#points-table tbody tr.fresh") < total

        await page.wait_for("!document.querySelectorAll('#points-table tbody tr.fresh').length")
        await page.click("[data-scan='integrity']")
        await page.wait_for("!document.querySelector('#result-card').hidden")
        assert await page.count("#points-table tbody tr.fresh") == 0

        await page.click("#point-changed")
        console.simulation.advance(5.0)
        await page.wait_for("document.querySelectorAll('#points-table tbody tr').length")
        assert 0 < await page.count("#points-table tbody tr") < total

    @pytest.mark.asyncio
    async def test_the_filter_narrows_it(self, console):
        page = console.page
        await console.tab("points")
        await page.wait_for("document.querySelectorAll('#points-table tbody tr').length")
        power = der.AI_METER_FIRST + 4
        await page.evaluate(
            f"document.querySelector('#point-filter').value = '{power}';"
            "document.querySelector('#point-filter').dispatchEvent(new Event('input'))"
        )
        rows = await page.evaluate(
            "[...document.querySelectorAll('#points-table tbody tr')]"
            ".map(row => row.cells[0].textContent)"
        )
        assert str(power) in rows and len(rows) < console.served(Kind.AI)


class TestEnumerations:
    async def _row(self, console) -> str:
        await console.tab("points")
        await console.page.wait_for("document.querySelectorAll('#points-table tbody tr').length")
        return (
            "[...document.querySelectorAll('#points-table tbody tr')]"
            f".find(row => row.cells[0].textContent === '{ENUMERATED}')"
        )

    @pytest.mark.asyncio
    async def test_an_enumerated_points_name_stands_alone_with_a_mark_beside_it(self, console):
        page = console.page
        row = await self._row(console)
        assert await page.evaluate(f"{row}.cells[1].textContent") == "Operating Modei"
        assert await page.evaluate(f"{row}.cells[1].firstChild.textContent") == "Operating Mode"
        assert await page.evaluate(f"{row}.querySelectorAll('.info').length") == 1
        assert "<0>" not in await page.text("#points-table")
        # Every other point is as it was, with no mark.
        assert await page.count("#points-table .info") == 1

    @pytest.mark.asyncio
    async def test_pointing_at_the_mark_lists_the_values_one_to_a_line(self, console):
        page = console.page
        row = await self._row(console)
        assert await page.evaluate("document.querySelector('.tip').hidden")
        await page.evaluate(f"{row}.scrollIntoView({{block: 'center'}})")

        await page.evaluate(
            f"{row}.querySelector('.info').dispatchEvent(new MouseEvent('mouseenter'))"
        )

        assert not await page.evaluate("document.querySelector('.tip').hidden")
        assert await page.text(".tip") == "0: Off\n1: Following the grid\n11-255: Reserved"
        assert await page.evaluate(
            "getComputedStyle(document.querySelector('.tip')).whiteSpace"
        ) == ("pre-line")
        shown = await page.evaluate(
            "(() => { const box = document.querySelector('.tip').getBoundingClientRect();"
            " return box.width > 0 && box.left >= 0 && box.right <= innerWidth"
            " && box.top >= 0 && box.bottom <= innerHeight; })()"
        )
        assert shown, "the list is on the screen, and not cut off by the table"

        await page.evaluate(
            f"{row}.querySelector('.info').dispatchEvent(new MouseEvent('mouseleave'))"
        )
        assert await page.evaluate("document.querySelector('.tip').hidden")

    @pytest.mark.asyncio
    async def test_the_mark_can_be_reached_from_the_keyboard(self, console):
        page = console.page
        row = await self._row(console)
        # The row is far down the table, so reaching its mark scrolls the table.
        await page.evaluate(f"{row}.querySelector('.info').focus()")
        await asyncio.sleep(0.3)
        assert not await page.evaluate("document.querySelector('.tip').hidden")
        on_screen = await page.evaluate(
            "(() => { const box = document.querySelector('.tip').getBoundingClientRect();"
            " return box.top >= 0 && box.bottom <= innerHeight; })()"
        )
        assert on_screen
        label = await page.evaluate(f"{row}.querySelector('.info').getAttribute('aria-label')")
        assert label == "Values: 0 Off, 1 Following the grid, 11-255 Reserved"
        await page.evaluate(f"{row}.querySelector('.info').blur()")
        assert await page.evaluate("document.querySelector('.tip').hidden")


class TestPointsNotReported:
    @pytest.mark.asyncio
    async def test_the_profiles_other_points_are_shown_when_asked_for(self, console):
        """Nobody has read the outputs, so every one is in the profile and not reported."""
        page = console.page
        outputs = console.served(Kind.AO)
        await console.tab("points")
        await console.point_type("ao")
        assert await page.count("#points-table tbody tr") == 0
        assert "not part of an integrity poll" in await page.text("#point-summary")
        assert not await page.evaluate("document.querySelector('#point-unreported-label').hidden")

        await page.click("#point-unreported")

        assert await page.count("#points-table tbody tr.unreported") == outputs
        assert f"0 reported and {outputs} not, of {outputs}" in await page.text("#point-summary")
        assert "NOT REPORTED" in await page.text("#points-table tbody tr.unreported")
        assert f"0 of {outputs}" in await page.text("#point-types")

        await page.click("#point-unreported")
        assert await page.count("#points-table tbody tr") == 0

    @pytest.mark.asyncio
    async def test_a_point_moves_across_when_it_is_read(self, console):
        page = console.page
        outputs = console.served(Kind.AO)
        await console.tab("points")
        await console.point_type("ao")
        await page.click("#point-unreported")
        assert await page.count("#points-table tbody tr.unreported") == outputs

        await page.click("[data-scan='outputs']")

        await page.wait_for(
            "!document.querySelectorAll('#points-table tbody tr.unreported').length"
        )
        assert await page.count("#points-table tbody tr") == outputs
        assert f"{outputs} reported and 0 not" in await page.text("#point-summary")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_with_no_profile_the_box_is_not_offered(self, console):
        page = console.page
        await console.service.handle(
            {
                "op": "add",
                "params": {"name": "plain", "host": "127.0.0.1", "port": 1, "connect": False},
            }
        )
        await page.wait_for("document.querySelectorAll('#outstations li').length === 2")
        await page.evaluate("select('plain')")
        await page.wait_for("document.querySelector('#title').textContent === 'plain'")
        # Not on the page, which is more than being marked hidden: a stylesheet
        # that gives its kind of element a display can leave a hidden one showing.
        assert (
            await page.evaluate(
                "getComputedStyle(document.querySelector('#point-unreported-label')).display"
            )
            == "none"
        )


class TestCommands:
    @pytest.mark.asyncio
    async def test_a_scan_shows_what_came_of_it(self, console):
        page = console.page
        await console.tab("commands")
        await page.click("[data-scan='integrity']")
        await page.wait_for("!document.querySelector('#result-card').hidden")

        assert await page.text("#result .outcome") == "complete"
        result = await page.text("#result")
        assert "READ" in result and "DEVICE_RESTART" in result
        assert await page.count("#result table tbody tr") > 0

    @pytest.mark.asyncio
    async def test_a_read_of_named_points(self, console):
        page = console.page
        await console.tab("commands")
        await page.evaluate(
            "(() => { const form = document.querySelector('#read-form');"
            " form.elements.type.value = 'bi'; form.elements.indices.value = '0, 1';"
            " form.requestSubmit(); })()"
        )
        await page.wait_for("document.querySelectorAll('#result table tbody tr').length === 2")
        assert await page.text("#result .outcome") == "complete"

    @pytest.mark.asyncio
    async def test_a_request_the_outstation_refuses_says_so(self, console):
        page = console.page
        await console.tab("commands")
        await page.evaluate(
            "(() => { const form = document.querySelector('#read-form');"
            " form.elements.type.value = 'ai'; form.elements.indices.value = '60000';"
            " form.requestSubmit(); })()"
        )
        await page.wait_for("document.querySelector('#result').textContent.includes('PARAM_ERROR')")
        assert await page.text("#result .outcome") == "complete"

    @pytest.mark.asyncio
    async def test_a_scan_is_repeated_from_the_form(self, console):
        page = console.page
        await console.tab("commands")
        await page.evaluate(
            "(() => { const form = document.querySelector('#repeat-form');"
            " form.elements.outputs.value = '5'; form.requestSubmit(); })()"
        )
        await page.wait_for("(state.points.ao || new Map()).size > 0")
        (lab,) = (await console.service.handle({"op": "status"}))["result"]["outstations"]
        assert lab["repeat"]["outputs"] == 5.0


def _operate(output: str, index: int, value, mode: str = "select") -> str:
    """The script that fills the operate form in as a person would, and submits it."""
    field = "operation" if output == "bo" else "value"
    return (
        "(() => { const form = document.querySelector('#operate-form');"
        f" form.elements.type.value = '{output}';"
        " form.elements.type.dispatchEvent(new Event('change'));"
        f" form.elements.index.value = '{index}'; form.elements.{field}.value = '{value}';"
        f" form.elements.mode.value = '{mode}'; form.requestSubmit(); }})()"
    )


class TestReadOnly:
    """A console over a service that was not started to command."""

    @pytest.mark.asyncio
    async def test_it_says_so_and_offers_no_way_to_operate(self, console):
        page = console.page
        assert await page.text("#control-state") == "Read only"
        await console.tab("commands")
        assert await page.evaluate("document.querySelector('#operate-fields').disabled")
        assert "--allow-control" in await page.text("#control-off")
        assert await page.evaluate(
            "[...document.querySelectorAll('#write-buttons button')].every((b) => b.disabled)"
        )

    @pytest.mark.asyncio
    async def test_an_outputs_row_has_no_button(self, console):
        page = console.page
        await console.tab("commands")
        await page.click("[data-scan='outputs']")
        await page.wait_for("(state.points.ao || new Map()).size > 0")
        await console.tab("points")
        await console.point_type("ao")
        assert await page.count("#points-table tbody tr") > 0
        assert await page.count("#points-table td.act") == 0

    @pytest.mark.asyncio
    async def test_the_service_refuses_even_if_the_page_is_made_to_ask(self, console):
        """The page hiding a control is a courtesy. The refusal is the service's."""
        page = console.page
        await console.tab("commands")
        await page.evaluate("document.querySelector('#operate-fields').disabled = false")
        await page.evaluate(_operate("ao", 87, 20, "direct"))
        await page.wait_for("document.querySelector('#result .error') !== null")
        assert "--allow-control" in await page.text("#result .error")
        assert console.simulation.outstation.value(Kind.AO, 87) == 100.0


@commanding
class TestCommanding:
    """A console over a service started with --allow-control."""

    @pytest.mark.asyncio
    async def test_it_says_that_it_can_command(self, console):
        page = console.page
        assert await page.text("#control-state") == "Commanding on"
        await console.tab("commands")
        assert not await page.evaluate("document.querySelector('#operate-fields').disabled")
        assert await page.evaluate("document.querySelector('#control-off').hidden")

    @pytest.mark.asyncio
    async def test_a_select_and_operate_shows_both_requests_and_each_status(self, console):
        page = console.page
        await console.tab("commands")
        await page.evaluate(_operate("ao", 87, 20))
        await page.wait_for("document.querySelector('#result .verdict') !== null")

        assert await page.text("#result .verdict") == "Accepted"
        requests = await page.text("#result .facts")
        assert "SELECT" in requests and "OPERATE" in requests
        assert await page.count("#operated-table tbody tr") == 1
        row = await page.text("#operated-table tbody tr")
        assert "Analog output" in row and "87" in row and "SUCCESS" in row and "Yes" in row
        assert console.simulation.outstation.value(Kind.AO, 87) == 20

    @pytest.mark.asyncio
    async def test_the_outputs_status_is_read_back_into_the_points_table(self, console):
        page = console.page
        # Output status is in no scan this console repeats, so it is not there yet.
        assert await page.evaluate("(state.points.ao || new Map()).has(87)") is False
        await console.tab("commands")
        await page.evaluate(_operate("ao", 87, 20, "direct"))
        await page.wait_for("(state.points.ao || new Map()).has(87)")
        assert await page.evaluate("state.points.ao.get(87).value") == 20

    @pytest.mark.asyncio
    async def test_a_binary_output_is_latched(self, console):
        page = console.page
        await console.tab("commands")
        await page.evaluate(_operate("bo", 17, "latch_on", "direct"))
        await page.wait_for("document.querySelector('#result .verdict') !== null")
        assert await page.text("#result .verdict") == "Accepted"
        assert "Latch on" in await page.text("#operated-table tbody tr")
        assert console.simulation.outstation.value(Kind.BO, 17) is True

    @pytest.mark.asyncio
    async def test_the_fields_shown_are_the_ones_the_output_takes(self, console):
        page = console.page
        await console.tab("commands")
        shown = (
            "[...document.querySelectorAll('#operate-form [data-for]')]"
            ".filter((label) => getComputedStyle(label).display !== 'none')"
            ".map((label) => label.dataset.for)"
        )
        assert set(await page.evaluate(shown)) == {"ao"}
        await page.evaluate(
            "(() => { const type = document.querySelector('#operate-form').elements.type;"
            " type.value = 'bo'; type.dispatchEvent(new Event('change')); })()"
        )
        assert set(await page.evaluate(shown)) == {"bo"}

    @pytest.mark.asyncio
    async def test_a_refused_select_is_shown_as_not_operated(self, console):
        page = console.page
        locked = await console.service.handle(
            {"op": "operate", "outstation": "lab", "params": {"points": {"bo": {"0": True}}}}
        )
        assert locked["result"]["accepted"]
        await console.tab("commands")
        await page.evaluate(_operate("ao", 87, 20))
        await page.wait_for("document.querySelector('#result .verdict') !== null")

        assert await page.text("#result .verdict") == "Not operated"
        result = await page.text("#result")
        assert "BLOCKED" in result and "no operate was sent" in result
        assert "OPERATE" not in await page.text("#result .facts")
        assert console.simulation.outstation.value(Kind.AO, 87) == 100.0

    @pytest.mark.asyncio
    async def test_no_acknowledgment_is_shown_as_not_known_and_not_as_refused(self, console):
        page = console.page
        await console.tab("commands")
        await page.evaluate(_operate("ao", 87, 40, "direct_no_ack"))
        await page.wait_for("document.querySelector('#result .verdict') !== null")
        assert await page.text("#result .verdict") == "Not known"
        assert "may have been operated" in await page.text("#result")
        assert "no answer" in await page.text("#operated-table tbody tr")

    @pytest.mark.asyncio
    async def test_the_time_is_written_and_the_restart_indication_cleared(self, console):
        page = console.page
        await console.tab("commands")
        await page.click("[data-write='write_time']")
        await page.wait_for("document.querySelector('#result').textContent.includes('WRITE')")
        assert "NEED_TIME" not in await page.text("#result")
        await page.click("[data-write='clear_restart']")
        await page.wait_for("!document.querySelector('#result').textContent.includes('NEED_TIME')")
        await page.wait_for(
            "!document.querySelector('#result').textContent.includes('DEVICE_RESTART')"
        )
        await page.click("[data-write='freeze_clear']")
        await page.wait_for(
            "document.querySelector('#result').textContent.includes('FREEZE_CLEAR')"
        )

    @pytest.mark.asyncio
    async def test_an_outputs_row_leads_to_the_form_filled_in(self, console):
        page = console.page
        await console.tab("commands")
        await page.click("[data-scan='outputs']")
        await page.wait_for("(state.points.ao || new Map()).size > 0")
        await console.tab("points")
        await console.point_type("ao")
        rows = await page.count("#points-table tbody tr")
        assert rows > 0 and await page.count("#points-table td.act button") == rows
        index = await page.evaluate(
            "Number(document.querySelector('#points-table tbody tr td').textContent)"
        )

        await page.click("#points-table tbody tr td.act button")

        assert await page.evaluate("state.tab") == "commands"
        form = "document.querySelector('#operate-form').elements"
        assert await page.evaluate(f"{form}.type.value") == "ao"
        assert await page.evaluate(f"Number({form}.index.value)") == index
        # The age is still the cell that ticks, with the button after it.
        await console.tab("points")
        assert await page.evaluate(
            "document.querySelector('#points-table tbody tr td.age').textContent.length > 0"
        )


class TestEventsAndTraffic:
    @pytest.mark.asyncio
    async def test_events_are_listed_as_they_arrive(self, console):
        page = console.page
        await console.tab("events")
        console.simulation.advance(5.0)
        # The newest is first. Wait for one that arrived while the page was
        # watching: how an event from before that was reported, it cannot say.
        await page.wait_for(
            "(document.querySelector('#events-table tbody tr') || {cells: []}).cells[7]"
            "?.textContent === 'Polled'"
        )
        first = await page.evaluate(
            "[...document.querySelector('#events-table tbody tr').cells].map(c => c.textContent)"
        )
        assert first[1] in ("Analog inputs", "Binary inputs", "Frozen counters", "Counters")
        assert first[7] == "Polled"

    @pytest.mark.asyncio
    async def test_a_frame_is_read_layer_by_layer_beside_its_octets(self, console):
        page = console.page
        await console.tab("traffic")
        await page.wait_for("document.querySelectorAll('#traffic-table tbody tr').length")
        await page.wait_for("document.querySelectorAll('#frame-detail .layer').length")

        layers = await page.evaluate(
            "[...document.querySelectorAll('#frame-detail .layer h4')]"
            ".map(heading => heading.textContent.trim())"
        )
        assert layers[:3] == ["Data link", "Transport", "Application"]
        octets = await page.count("#frame-detail .octet")
        assert octets == await page.evaluate("state.frame.octets.length / 2")
        assert await page.text("#frame-detail .octet") == "05", "a frame starts 05 64"
        assert await page.count("#frame-detail .octet.transport") == 1
        assert "[object" not in await page.text("#frame-detail")

    @pytest.mark.asyncio
    async def test_the_traffic_can_be_narrowed_paused_and_cleared(self, console):
        page = console.page
        await console.tab("traffic")
        await page.wait_for("document.querySelectorAll('#traffic-table tbody tr').length > 2")

        await page.click("#traffic-direction [data-direction='tx']")
        shown = await page.evaluate(
            "[...document.querySelectorAll('#traffic-table td.direction')].map(c => c.title)"
        )
        assert shown and set(shown) == {"Sent"}

        await page.click("#traffic-pause")
        held = await page.evaluate("state.frames.length")
        await asyncio.sleep(1.2)
        assert await page.evaluate("state.frames.length") == held

        await page.click("#traffic-clear")
        await page.wait_for("!document.querySelectorAll('#traffic-table tbody tr').length")
        assert page.errors == []


class TestWithAToken:
    """Started with a token, the page still has to load, and then to carry it."""

    @pytest_asyncio.fixture
    async def guarded(self):
        point_map = load.resolve(for_reference_der(), Composition())
        simulation = der.build(point_map)
        outstation = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
        service = Service()
        http = HttpServer(service, bind="127.0.0.1:0", token="s3cret")
        await outstation.start()
        await http.start()
        try:
            added = await service.handle(
                {
                    "op": "add",
                    "params": {"name": "lab", "host": "127.0.0.1", "port": outstation.port},
                }
            )
            assert added["ok"], added
            await service.handle({"op": "scan", "outstation": "lab"})
            async with open_page() as page:
                yield page, http
        finally:
            await service.close()
            await http.stop()
            await outstation.stop()

    @pytest.mark.asyncio
    async def test_opened_at_the_address_it_printed_it_works(self, guarded):
        page, http = guarded
        await page.goto(http.url)
        await page.wait_for("document.querySelector('#title')?.textContent === 'lab'")
        await page.wait_for("document.querySelector('#service-state').classList.contains('good')")
        # Styled, which it is not if the stylesheet was refused for want of a token.
        assert (
            await page.evaluate("getComputedStyle(document.querySelector('.masthead')).display")
            == "flex"
        )
        assert await page.evaluate("(state.points.ai || new Map()).size") > 0
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_opened_without_the_token_it_shows_nothing_of_the_outstation(self, guarded):
        page, http = guarded
        await page.goto(http.url.split("?")[0])
        await page.wait_for("document.querySelector('#service-state').classList.contains('bad')")
        assert await page.count("#outstations .name") == 0
        assert await page.evaluate("document.querySelector('#workspace').hidden")


class TestWhatItWillNotDo:
    @pytest.mark.asyncio
    async def test_a_name_is_shown_as_text_and_never_run(self, console):
        """An outstation is named by whoever adds it, and the page must not trust the name."""
        page = console.page
        name = '<img src=x onerror="window.pwned = 1">'
        added = await console.service.handle(
            {
                "op": "add",
                "params": {"name": name, "host": "127.0.0.1", "port": 1, "connect": False},
            }
        )
        assert added["ok"]
        await page.wait_for("document.querySelectorAll('#outstations li').length === 2")
        await page.evaluate(f"select({name!r})")
        await page.wait_for(f"document.querySelector('#title').textContent === {name!r}")

        assert await page.evaluate("typeof window.pwned") == "undefined"
        assert await page.count("#outstations img, #title img") == 0
        assert name in await page.text("#outstations")

    @pytest.mark.asyncio
    async def test_an_outstation_that_cannot_be_reached_is_added_and_said_to_be(self, console):
        page = console.page
        closed = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
        port = closed.sockets[0].getsockname()[1]
        closed.close()
        await closed.wait_closed()

        await page.evaluate(
            "(() => { const form = document.querySelector('#add-form');"
            " form.elements.name.value = 'unreachable'; form.elements.host.value = '127.0.0.1';"
            f" form.elements.port.value = '{port}'; form.requestSubmit(); }})()"
        )

        await page.wait_for("document.querySelector('#add-error').textContent")
        await page.wait_for("document.querySelectorAll('#outstations li').length === 2")
        assert await page.count("#outstations .lamp.off") == 1
