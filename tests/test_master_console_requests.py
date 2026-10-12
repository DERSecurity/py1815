"""The console's Requests tab, loaded in a real browser against the simulated DER.

The tab holds no logic: a saved request is a function code by name and object
headers in hexadecimal, and the service's ``request`` operation is what sends
it and what refuses it. What is tested here is the page: that it starts with a
list, keeps the reader's own in the browser, sends one and shows the exchange,
repeats one on its own timer until stopped, and shows a refusal. A machine
with no browser skips these; see ``browser.py``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest
import pytest_asyncio
from browser import Page, open_page
from profile_fixtures import for_reference_der

from py1815.master.service import HttpServer, Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

#: The requests a browser that has saved none starts with: name, function code
#: and object headers.
STARTING = [
    ["Integrity poll", "READ", "3C 02 06 3C 03 06 3C 04 06 3C 01 06"],
    ["Event poll (Class 1, 2, 3)", "READ", "3C 02 06 3C 03 06 3C 04 06"],
    ["Class 0", "READ", "3C 01 06"],
    ["Binary inputs, all", "READ", "01 00 06"],
]

LISTED = (
    "[...document.querySelectorAll('#requests-table tbody tr[data-request]')]"
    ".map((row) => [0, 1, 2].map((cell) => row.cells[cell].textContent))"
)


@dataclass
class Console:
    page: Page
    service: Service
    simulation: der.Simulation
    http: HttpServer

    async def ask(self, op: str, **params):
        answer = await self.service.handle({"op": op, "outstation": "lab", "params": params})
        assert answer["ok"], answer
        return answer["result"]

    def sent(self) -> int:
        """Return how many frames have crossed the wire, in either direction."""
        return self.service.master["lab"].trace.last_id


#: For a test of the tab over a service started to command.
commanding = pytest.mark.parametrize("console", [True], indirect=True)


async def _open(page: Page, http: HttpServer) -> None:
    """Load the console afresh and open its Requests tab.

    The page that is there is marked first, and the mark has to be gone: a
    wait that the page before the load also satisfies proves nothing loaded.
    """
    await page.evaluate("window.loadedBefore = true")
    await page.goto(http.url)
    await page.wait_for("window.loadedBefore === undefined && typeof saved === 'object'")
    await page.wait_for("document.querySelector('#title').textContent === 'lab'")
    await page.click(".tabs [data-tab='requests']")
    await page.wait_for("document.querySelectorAll('#requests-table tbody tr').length")


@pytest_asyncio.fixture
async def console(request):
    """The console in a browser, on its Requests tab, with the simulated DER added.

    The outstation is added with nothing sent unasked, so every frame is one a
    saved request caused, and with a short response timeout.
    """
    points = load.resolve(for_reference_der(), Composition())
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
                },
            }
        )
        assert added["ok"], added
        async with open_page() as page:
            await _open(page, http)
            yield Console(page, service, simulation, http)
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


def _row(name: str) -> str:
    """Return the expression for the row of the saved request with a name."""
    return (
        "[...document.querySelectorAll('#requests-table tbody tr[data-request]')]"
        f".find((row) => row.cells[0].textContent === {name!r})"
    )


def _press(name: str, action: str) -> str:
    """Return the script that presses one of a saved request's buttons."""
    return f"{_row(name)}.querySelector(\"[data-action='{action}']\").click()"


def _save(name: str, function: str, body: str) -> str:
    """Return the script that fills the form in as a person would, and submits it."""
    return (
        "(() => { const form = document.querySelector('#request-form');"
        f" form.elements.name.value = {name!r}; form.elements.function.value = {function!r};"
        f" form.elements.body.value = {body!r}; form.requestSubmit(); }})()"
    )


class TestTheList:
    @pytest.mark.asyncio
    async def test_a_browser_that_has_saved_none_starts_with_a_few_reads(self, console):
        page = console.page
        assert await page.evaluate(LISTED) == STARTING
        assert "sent by this page" in await page.text("[data-panel='requests'] .toolbar")
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_a_request_is_added_kept_over_a_reload_changed_and_removed(self, console):
        page = console.page
        await page.evaluate(_save("Analog inputs 2 to 4", "read", "1E 00 00 02 04"))
        added = ["Analog inputs 2 to 4", "read", "1E 00 00 02 04"]
        assert await page.evaluate(LISTED) == [*STARTING, added]
        # The form is empty again, for the next one.
        assert (
            await page.evaluate("document.querySelector('#request-form').elements.name.value") == ""
        )

        await _open(page, console.http)
        assert await page.evaluate(LISTED) == [*STARTING, added]

        await page.evaluate(_press("Analog inputs 2 to 4", "edit"))
        form = "document.querySelector('#request-form').elements"
        assert await page.evaluate(f"{form}.body.value") == "1E 00 00 02 04"
        assert await page.text("#request-save") == "Save"
        await page.evaluate(_save("Analog inputs 2 to 6", "READ", "1E 00 00 02 06"))
        changed = ["Analog inputs 2 to 6", "READ", "1E 00 00 02 06"]
        assert await page.evaluate(LISTED) == [*STARTING, changed]
        assert await page.text("#request-save") == "Add"

        await page.evaluate(_press("Class 0", "remove"))
        kept = [entry for entry in STARTING if entry[0] != "Class 0"]
        assert await page.evaluate(LISTED) == [*kept, changed]

        await _open(page, console.http)
        assert await page.evaluate(LISTED) == [*kept, changed]
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_the_list_is_kept_under_the_address_the_console_was_opened_at(self, console):
        page = console.page
        await page.evaluate(_save("Mine", "READ", "3C 01 06"))
        keys = await page.evaluate("Object.keys(localStorage)")
        origin = console.http.url.rstrip("/")
        assert keys == [f"py1815-master.requests:{origin}/"]


class TestSending:
    @pytest.mark.asyncio
    async def test_send_shows_the_exchange(self, console):
        page = console.page
        assert await page.evaluate("document.querySelector('#request-result-card').hidden")
        before = console.sent()

        await page.evaluate(_press("Integrity poll", "send"))

        await page.wait_for("document.querySelector('#request-result .outcome') !== null")
        assert await page.text("#request-result .outcome") == "complete"
        result = await page.text("#request-result")
        assert "READ" in result and "DEVICE_RESTART" in result
        assert await page.count("#request-result table tbody tr") > 0
        assert "Integrity poll" in await page.text("#request-result-of")
        assert "complete" in await page.evaluate(f"{_row('Integrity poll')}.cells[4].textContent")
        # One request was sent, and its object headers are the ones saved.
        (sent,) = [
            frame
            for frame in (await console.ask("trace", after=before))["frames"]
            if frame["direction"] == "tx"
        ]
        assert sent["application"]["objects"] == ["class 1", "class 2", "class 3", "class 0"]
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_an_answer_with_no_objects_shows_only_the_facts(self, console):
        page = console.page
        await page.evaluate(_save("Delay", "DELAY_MEASURE", ""))
        assert await page.evaluate(f"{_row('Delay')}.cells[2].textContent") == "none"

        await page.evaluate(_press("Delay", "send"))

        await page.wait_for("document.querySelector('#request-result .outcome') !== null")
        assert "DELAY_MEASURE" in await page.text("#request-result .facts")
        assert await page.evaluate("document.querySelector('#request-result').children.length") == 1
        assert "null" not in await page.text("#request-result")

    @pytest.mark.asyncio
    async def test_headers_the_service_cannot_read_are_said_and_nothing_is_sent(self, console):
        page = console.page
        await page.evaluate(_save("Not octets", "READ", "3C 0Z"))
        before = console.sent()

        await page.evaluate(_press("Not octets", "send"))

        await page.wait_for("document.querySelector('#request-result .error') !== null")
        assert "in hexadecimal" in await page.text("#request-result .error")
        assert "failed" in await page.evaluate(f"{_row('Not octets')}.cells[4].textContent")
        assert console.sent() == before

    @pytest.mark.asyncio
    async def test_a_function_code_that_commands_is_refused_when_commanding_is_off(self, console):
        page = console.page
        await page.evaluate(_save("Freeze counters", "IMMED_FREEZE", "14 00 06"))
        before = console.sent()

        await page.evaluate(_press("Freeze counters", "send"))

        await page.wait_for("document.querySelector('#request-result .error') !== null")
        refusal = await page.text("#request-result .error")
        assert "commanding is off" in refusal and "--allow-control" in refusal
        assert "failed" in await page.evaluate(f"{_row('Freeze counters')}.cells[4].textContent")
        assert console.sent() == before, "nothing was sent"

    @pytest.mark.asyncio
    @commanding
    async def test_a_function_code_that_commands_is_sent_when_commanding_is_on(self, console):
        page = console.page
        await page.evaluate(_save("Freeze counters", "IMMED_FREEZE", "14 00 06"))

        await page.evaluate(_press("Freeze counters", "send"))

        await page.wait_for("document.querySelector('#request-result .outcome') !== null")
        assert await page.text("#request-result .outcome") == "complete"
        assert "IMMED_FREEZE" in await page.text("#request-result .facts")


class TestRepeating:
    @pytest.mark.asyncio
    async def test_repeat_sends_more_than_once_and_stop_ends_it(self, console):
        page = console.page
        row = _row("Class 0")
        await page.evaluate(
            f"(() => {{ const field = {row}.querySelector(\"input[type='number']\");"
            " field.value = '0.3'; field.dispatchEvent(new Event('change')); })()"
        )
        before = console.sent()

        await page.evaluate(_press("Class 0", "repeat"))

        await page.wait_for(f"/sent [3-9] time/.test({row}.cells[4].textContent)")
        assert "Every 0.3 s" in await page.evaluate(f"{row}.cells[3].textContent")
        requests = [
            frame
            for frame in (await console.ask("trace", after=before))["frames"]
            if frame["direction"] == "tx"
        ]
        assert len(requests) >= 3
        assert {frame["summary"].split(": ")[1] for frame in requests} == {"class 0"}

        await page.evaluate(_press("Class 0", "stop"))

        assert await page.evaluate(f"{row}.querySelector(\"[data-action='repeat']\") !== null")
        # A send that was under way when it was stopped may still end.
        await asyncio.sleep(0.4)
        ended = console.sent()
        await asyncio.sleep(1.0)
        assert console.sent() == ended, "nothing more was sent"
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_a_refusal_ends_a_repeat(self, console):
        page = console.page
        await page.evaluate(_save("Freeze counters", "IMMED_FREEZE", "14 00 06"))
        row = _row("Freeze counters")
        before = console.sent()

        await page.evaluate(_press("Freeze counters", "repeat"))

        await page.wait_for(f"{row}.cells[4].textContent.includes('The repeat stopped.')")
        assert await page.evaluate(f"{row}.querySelector(\"[data-action='repeat']\") !== null")
        assert "commanding is off" in await page.text("#request-result .error")
        assert console.sent() == before

    @pytest.mark.asyncio
    async def test_an_outstation_that_does_not_answer_ends_a_repeat(self, console):
        page = console.page
        row = _row("Class 0")
        # The master sends nothing, so the request times out.
        await console.ask("deviate", set={"silence": True})

        await page.evaluate(_press("Class 0", "repeat"))

        await page.wait_for(f"{row}.cells[4].textContent.includes('The repeat stopped.')")
        assert await page.text("#request-result .outcome") == "timeout"
        assert "timeout" in await page.evaluate(f"{row}.cells[4].textContent")
        assert await page.evaluate(f"{row}.querySelector(\"[data-action='repeat']\") !== null")

    @pytest.mark.asyncio
    async def test_selecting_another_outstation_ends_a_repeat(self, console):
        page = console.page
        row = _row("Class 0")
        added = await console.service.handle(
            {
                "op": "add",
                "params": {"name": "other", "host": "127.0.0.1", "port": 1, "connect": False},
            }
        )
        assert added["ok"]
        await page.wait_for("document.querySelectorAll('#outstations li').length === 2")
        await page.evaluate(_press("Class 0", "repeat"))
        await page.wait_for(f"/sent [1-9] time/.test({row}.cells[4].textContent)")

        await page.evaluate("select('other')")

        await page.wait_for("document.querySelector('#title').textContent === 'other'")
        assert await page.evaluate("saved.repeats.size") == 0
        assert await page.evaluate(f"{row}.querySelector(\"[data-action='repeat']\") !== null")
        assert await page.evaluate("document.querySelector('#request-result-card').hidden")
        await asyncio.sleep(0.4)
        ended = console.sent()
        await asyncio.sleep(1.0)
        assert console.sent() == ended, "nothing more was sent to the first outstation"
