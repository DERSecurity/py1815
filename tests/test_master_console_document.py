"""The console's Device Profile document card, loaded in a real browser.

The card holds no logic: the service reads the XML and answers with a title,
facts and sections of tables, which is tested at the reader and at the
service. What is tested here is the page: that it shows the model the service
answers with and nothing else, takes a file from the reader's disk, says what
the service says when there is no document or the file is not one, cannot be
made to run markup that a document carries, and prints the document alone. A
machine with no browser skips these; see ``browser.py``.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from typing import Any

import pytest
import pytest_asyncio
from browser import Page, open_page
from profile_fixtures import paired_reference_der

from py1815.master.service import HttpServer, Service
from py1815.profile import der, device_profile, load
from py1815.profile.model import Composition, Kind
from py1815.server import OutstationServer

#: Names a hostile document might give a point. Shown, they are text.
SCRIPT = "<script>window.injected = 'script'</script>"
IMAGE = "<img src=x onerror=\"window.injected = 'image'\">"

#: A Device Profile from somewhere else, small enough to state whole.
OTHER = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<DNP3DeviceProfileDocument xmlns="http://example.test/another-edition">'
    "<documentHeader><documentName>Widget Profile</documentName></documentHeader>"
    "<referenceDevice><configuration><linkConfig><dataLinkAddress>"
    "<capabilities><range><minimum>0</minimum><maximum>65519</maximum></range></capabilities>"
    "<currentValue><value>7</value></currentValue>"
    "</dataLinkAddress></linkConfig></configuration></referenceDevice>"
    "</DNP3DeviceProfileDocument>"
)

#: What the page shows of a document, in the shape the service answers in.
SHOWN = """(() => {
  const view = document.querySelector('#der-document-view');
  const text = (node) => node.textContent;
  const facts = [...view.querySelectorAll(':scope > dl > dt')].map((term) =>
    ({ label: text(term), value: text(term.nextElementSibling) }));
  const sections = [...view.querySelectorAll(':scope > section')].map((section) => ({
    title: text(section.querySelector(':scope > h3')),
    tables: [...section.querySelectorAll(':scope > .table-wrap')].map((wrap) => ({
      title: wrap.previousElementSibling.tagName === 'H4' ? text(wrap.previousElementSibling) : '',
      columns: [...wrap.querySelectorAll('thead th')].map(text),
      rows: [...wrap.querySelectorAll('tbody tr')].map((row) => [...row.cells].map(text)),
    })),
  }));
  return {
    title: text(view.querySelector(':scope > h2')),
    notice: text(view.querySelector(':scope > .document-notice')),
    facts,
    sections,
  };
})()"""


@dataclass
class Console:
    page: Page
    service: Service
    simulation: der.Simulation

    async def laid_out(self, **params: Any) -> dict[str, Any]:
        """Return what the service answers for the outstation's document."""
        answer = await self.service.handle(
            {"op": "der.document", "outstation": "lab", "params": params}
        )
        assert answer["ok"], answer
        result: dict[str, Any] = answer["result"]
        return result


@pytest_asyncio.fixture
async def console():
    """The console in a browser, on its DER tab, with the simulated DER added.

    The DER is given the Device Profile document it would publish. Two of its
    points are named with markup, as a document from elsewhere might name them.
    """
    point_map = load.resolve(paired_reference_der(), Composition())
    points = dict(point_map.points)
    served = sorted(index for kind, index in points if kind is Kind.BI)
    for index, name in zip(served, (SCRIPT, IMAGE), strict=False):
        points[(Kind.BI, index)] = dataclasses.replace(points[(Kind.BI, index)], name=name)
    point_map = dataclasses.replace(point_map, points=points)
    simulation = der.build(point_map)
    outstation = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    service = Service()
    http = HttpServer(service, bind="127.0.0.1:0")
    await outstation.start()
    await http.start()
    try:
        service.set_profile("lab", point_map)
        built = device_profile.build(simulation.outstation, simulation.outstation.session())
        service.set_device_profile("lab", device_profile.render(built))
        added = await service.handle(
            {"op": "add", "params": {"name": "lab", "host": "127.0.0.1", "port": outstation.port}}
        )
        assert added["ok"], added
        async with open_page() as page:
            await page.goto(http.url)
            await page.wait_for("document.querySelector('#title').textContent === 'lab'")
            await page.wait_for("!document.querySelector(\".tabs [data-tab='der']\").hidden")
            await page.click(".tabs [data-tab='der']")
            await page.wait_for("document.querySelector('#der-document-show') !== null")
            yield Console(page, service, simulation)
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


async def _show(page: Page) -> None:
    """Press Show, and wait for the document to be laid out."""
    await page.click("#der-document-show")
    await page.wait_for("document.querySelector('#der-document-view') !== null")


async def _choose(page: Page, name: str, text: str) -> None:
    """Choose a file from the reader's disk, as the file chooser would."""
    await page.evaluate(
        "(() => { const input = document.querySelector('#der-document-file');"
        " const chosen = new DataTransfer();"
        f" chosen.items.add(new File([{json.dumps(text)}], {json.dumps(name)},"
        " { type: 'text/xml' }));"
        " input.files = chosen.files;"
        " input.dispatchEvent(new Event('change', { bubbles: true })); })()"
    )


def _table(shown: dict[str, Any], section: str, title: str) -> dict[str, Any]:
    (found,) = [part for part in shown["sections"] if part["title"] == section]
    (table,) = [each for each in found["tables"] if each["title"] == title]
    result: dict[str, Any] = table
    return result


class TestShow:
    @pytest.mark.asyncio
    async def test_nothing_is_laid_out_and_no_print_is_offered_until_asked(self, console):
        page = console.page
        assert await page.text("#der-document h3") == (
            "Device Profile document laid out for reading and printing"
        )
        assert await page.count("#der-document-view") == 0
        assert await page.count("#der-document-print") == 0
        assert await page.count("#der-document-error") == 0

    @pytest.mark.asyncio
    async def test_show_lays_out_the_document_the_outstation_was_given(self, console):
        page = console.page
        await _show(page)

        shown = await page.evaluate(SHOWN)

        assert shown["title"] == "py1815 DER outstation Device Profile"
        link = _table(shown, "Configuration", "Link config")
        assert link["columns"] == ["Item", "Capabilities", "Current value"]
        assert link["rows"][0] == ["Data link address", "0 to 65519", "1024"]
        assert link["rows"][1] == [
            "Source address validation",
            "Never\nAlways single address",
            "Always single address",
        ]
        outputs = _table(shown, "Data points list", "Analog output points")
        served = console.simulation.outstation.served(Kind.AO)
        position = outputs["columns"].index("Index")
        assert [row[position] for row in outputs["rows"]] == [str(point.index) for point in served]
        assert [section["title"] for section in shown["sections"]] == [
            "Document header",
            "Configuration",
            "Database",
            "Implementation table",
            "Data points list",
        ]
        assert not await page.evaluate("document.querySelector('#der-document-print') === null")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_what_is_shown_is_the_model_the_service_answers_with(self, console):
        """Every title, heading and cell is the service's: the page adds and drops nothing."""
        page = console.page
        await _show(page)
        assert await page.evaluate(SHOWN) == await console.laid_out()

    @pytest.mark.asyncio
    async def test_a_cell_that_states_several_things_shows_one_to_a_line(self, console):
        page = console.page
        await _show(page)
        wraps = await page.evaluate(
            "getComputedStyle(document.querySelector('#der-document-view td')).whiteSpace"
        )
        assert wraps == "pre-line"

    @pytest.mark.asyncio
    async def test_it_asks_the_outside_world_for_nothing(self, console):
        page = console.page
        await _show(page)
        own = (await page.evaluate("location.origin")).rstrip("/")
        assert page.requests, "the page did load something"
        assert [url for url in page.requests if not url.startswith(own)] == []


class TestAFileFromDisk:
    @pytest.mark.asyncio
    async def test_a_device_profile_file_chosen_from_disk_is_laid_out(self, console):
        page = console.page
        await _choose(page, "vendor.xml", OTHER)
        await page.wait_for(
            "document.querySelector('#der-document-view h2')?.textContent === 'Widget Profile'"
        )

        shown = await page.evaluate(SHOWN)

        assert shown == await console.laid_out(document=OTHER)
        assert shown["facts"] == [{"label": "Document name", "value": "Widget Profile"}]
        assert shown["sections"] == [
            {
                "title": "Configuration",
                "tables": [
                    {
                        "title": "Link config",
                        "columns": ["Item", "Capabilities", "Current value"],
                        "rows": [["Data link address", "0 to 65519", "7"]],
                    }
                ],
            }
        ]
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_a_file_replaces_the_outstations_document_and_show_brings_it_back(self, console):
        page = console.page
        await _show(page)
        await _choose(page, "vendor.xml", OTHER)
        await page.wait_for(
            "document.querySelector('#der-document-view h2')?.textContent === 'Widget Profile'"
        )
        assert await page.count("#der-document-view") == 1

        await page.click("#der-document-show")

        await page.wait_for(
            "document.querySelector('#der-document-view h2')?.textContent"
            " === 'py1815 DER outstation Device Profile'"
        )
        assert await page.count("#der-document-view") == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("text", "says"),
        [
            (
                "<html><body>A page</body></html>",
                "the document is not a Device Profile: its root element is html, "
                "not DNP3DeviceProfileDocument",
            ),
            ("These are notes, not XML.", "the document is not XML: "),
        ],
    )
    async def test_a_file_that_is_not_a_device_profile_shows_what_the_service_says(
        self, console, text, says
    ):
        page = console.page
        await _show(page)
        refused = await console.service.handle(
            {"op": "der.document", "outstation": "lab", "params": {"document": text}}
        )
        assert refused["error"]["message"].startswith(says)

        await _choose(page, "notes.xml", text)

        await page.wait_for("document.querySelector('#der-document-error') !== null")
        assert await page.text("#der-document-error") == refused["error"]["message"]
        # The document shown before is not left on the page as if it were this file.
        assert await page.count("#der-document-view") == 0
        assert await page.count("#der-document-print") == 0
        assert page.errors == []


class TestWithNoDocument:
    @pytest.mark.asyncio
    async def test_an_outstation_given_no_document_shows_what_the_service_says(self, console):
        page = console.page
        await _show(page)
        console.service.set_profile("bare", console.simulation.outstation.point_map)
        added = await console.service.handle(
            {
                "op": "add",
                "params": {"name": "bare", "host": "127.0.0.1", "port": 1, "connect": False},
            }
        )
        assert added["ok"]
        await page.wait_for("document.querySelectorAll('#outstations li').length === 2")
        await page.evaluate("select('bare')")
        await page.wait_for("document.querySelector('#title').textContent === 'bare'")
        # The other outstation's document does not follow the reader here.
        await page.wait_for("document.querySelector('#der-document-view') === null")

        await page.click("#der-document-show")

        await page.wait_for("document.querySelector('#der-document-error') !== null")
        refused = await console.service.handle({"op": "der.document", "outstation": "bare"})
        assert await page.text("#der-document-error") == refused["error"]["message"]
        assert await page.text("#der-document-error") == (
            "bare was given no Device Profile document; send one as document, or give it "
            "with --device-profile"
        )
        assert await page.count("#der-document-view") == 0

        # A file from disk is still laid out: it needs no document of the outstation's.
        await _choose(page, "vendor.xml", OTHER)
        await page.wait_for(
            "document.querySelector('#der-document-view h2')?.textContent === 'Widget Profile'"
        )
        assert await page.count("#der-document-error") == 0
        assert page.errors == []


class TestMarkupInADocument:
    @pytest.mark.asyncio
    async def test_a_name_that_is_markup_is_shown_as_text_and_runs_nothing(self, console):
        page = console.page
        await _show(page)

        shown = await page.evaluate(SHOWN)

        inputs = _table(shown, "Data points list", "Binary input points")
        position = inputs["columns"].index("Name")
        assert [row[position] for row in inputs["rows"][:2]] == [SCRIPT, IMAGE]
        assert await page.count("#der-document-view script") == 0
        assert await page.count("#der-document-view img") == 0
        assert await page.evaluate("window.injected === undefined")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_a_title_and_a_fact_that_are_markup_are_shown_as_text(self, console):
        page = console.page
        hostile = OTHER.replace(
            "Widget Profile", SCRIPT.replace("&", "&amp;").replace("<", "&lt;")
        ).replace(
            "</documentHeader>",
            "<documentDescription>"
            + IMAGE.replace("&", "&amp;").replace("<", "&lt;")
            + "</documentDescription></documentHeader>",
        )
        await _choose(page, "hostile.xml", hostile)
        await page.wait_for("document.querySelector('#der-document-view') !== null")

        shown = await page.evaluate(SHOWN)

        assert shown["title"] == SCRIPT
        assert {"label": "Document description", "value": IMAGE} in shown["facts"]
        assert await page.count("#der-document-view script") == 0
        assert await page.count("#der-document-view img") == 0
        assert await page.evaluate("window.injected === undefined")
        assert page.errors == []


#: Whether an element is laid out, and so would be printed.
DISPLAYED = "getComputedStyle(document.querySelector({!r})).display !== 'none'"

#: What the console shows that is not the document.
CHROME = (
    ".masthead",
    ".sidebar",
    ".title-row",
    ".tabs",
    ".panel[data-panel='der'] .toolbar",
    "#der-nameplate",
    "#der-functions",
    "#der-comparison",
    "#der-document h3",
    "#der-document-show",
    "#der-document-print",
    "#der-document-file",
)


class TestPrint:
    @pytest.mark.asyncio
    async def test_print_prints_the_page_once_with_only_the_document_to_print(self, console):
        page = console.page
        await _show(page)
        # Keep the call instead of opening the browser's print dialog.
        await page.evaluate(
            "window.printed = [];window.print = () => window.printed.push(document.body.className);"
        )

        await page.click("#der-document-print")

        assert await page.evaluate("window.printed") == ["print-document"]
        await page.call("Emulation.setEmulatedMedia", media="print")
        try:
            for selector in CHROME:
                assert not await page.evaluate(DISPLAYED.format(selector)), selector
            assert await page.evaluate(DISPLAYED.format("#der-document-view"))
            assert await page.evaluate(
                "document.querySelector('#der-document-view table').getBoundingClientRect()"
                ".height > 0"
            )
            # The document is not clipped to the height of a card or a scrolling table.
            assert await page.evaluate(
                "[...document.querySelectorAll('#der-document-view .table-wrap')].every((wrap) =>"
                " getComputedStyle(wrap).maxHeight === 'none'"
                " && getComputedStyle(wrap).overflowY === 'visible')"
            )
            assert await page.evaluate(
                "['main', '.layout', 'body'].every((selector) =>"
                " getComputedStyle(document.querySelector(selector)).overflowY === 'visible')"
            )
            # A table's headings are repeated on each page, and a row is kept on one.
            assert await page.evaluate(
                "getComputedStyle(document.querySelector('#der-document-view thead')).display"
            ) == ("table-header-group")
            assert await page.evaluate(
                "getComputedStyle(document.querySelector('#der-document-view thead th')).position"
            ) == ("static")
            assert await page.evaluate(
                "getComputedStyle(document.querySelector('#der-document-view tbody tr'))"
                ".breakInside"
            ) == ("avoid")

            # When the browser is done printing, the console prints as itself again.
            await page.evaluate("window.dispatchEvent(new Event('afterprint'))")
            assert await page.evaluate("document.body.className") == ""
            assert await page.evaluate(DISPLAYED.format(".sidebar"))
            assert await page.evaluate(DISPLAYED.format("#der-nameplate"))
        finally:
            await page.call("Emulation.setEmulatedMedia", media="")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_on_the_screen_the_rest_of_the_console_stays_while_printing(self, console):
        """The rule that hides the console is a print rule, and not one for the screen."""
        page = console.page
        await _show(page)
        await page.evaluate("document.body.classList.add('print-document')")
        for selector in (".sidebar", ".tabs", "#der-nameplate", "#der-document-show"):
            assert await page.evaluate(DISPLAYED.format(selector)), selector
