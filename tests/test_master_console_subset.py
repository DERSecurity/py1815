"""The console's controls for the requests of Level 3 and Level 4.

The page builds no octets: it sends what was chosen to the service, which
refuses a request above the outstation's level and holds every write to the
service's permission to command. What is tested here is the page: that it
offers the level when an outstation is added, sends each request with what was
typed, shows a refusal, and leaves the controls that write off until the
service is started to command. A machine with no browser skips these; see
``browser.py``.
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


@dataclass
class Console:
    page: Page
    service: Service
    http: HttpServer

    @property
    def last(self):
        """The last exchange the outstation answered, or None."""
        return self.service.master["lab"].last_response

    async def request(self, after=None) -> str:
        """Wait for an exchange newer than ``after``, and return its request without the header.

        The first two octets of an application request are its control octet
        and function code; the object headers follow.
        """
        async with asyncio.timeout(5):
            while self.last is None or self.last is after:
                await asyncio.sleep(0.05)
        return self.last.request.hex()[4:]

    def frames_sent(self) -> int:
        trace = self.service.master["lab"].trace
        return len([entry for entry in trace.since() if entry.direction == "tx"])


#: The service's permission to command, and the level the outstation is added at.
as_level = pytest.mark.parametrize("console", [(False, 3)], indirect=True)
at_level_2 = pytest.mark.parametrize("console", [(False, 2)], indirect=True)
commanding_at_4 = pytest.mark.parametrize("console", [(True, 4)], indirect=True)
reading_at_4 = pytest.mark.parametrize("console", [(False, 4)], indirect=True)


@pytest_asyncio.fixture
async def console(request):
    """The console in a browser, with the simulated DER added at a level, sending nothing."""
    allow_control, level = getattr(request, "param", (False, 2))
    points = load.resolve(for_reference_der(), Composition())
    simulation = der.build(points)
    outstation = OutstationServer(
        simulation.outstation.session(need_time=False), bind="127.0.0.1:0"
    )
    service = Service(allow_control=allow_control)
    http = HttpServer(service, bind="127.0.0.1:0")
    await outstation.start()
    await http.start()
    try:
        added = await service.handle(
            {
                "op": "add",
                "params": {
                    "name": "lab",
                    "host": "127.0.0.1",
                    "port": outstation.port,
                    "response_timeout": 0.3,
                    "manual": True,
                    "level": level,
                },
            }
        )
        assert added["ok"], added
        async with open_page() as page:
            await page.goto(http.url)
            await page.wait_for("document.querySelector('#title').textContent === 'lab'")
            await page.click(".tabs [data-tab='commands']")
            yield Console(page, service, http)
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


def _fill(form: str, **fields: str) -> str:
    """Return the script that types into a form's fields as a person would, and submits it."""
    typed = "".join(f"form.elements[{name!r}].value = {value!r};" for name, value in fields.items())
    return (
        f"(() => {{ const form = document.querySelector('{form}'); {typed}"
        " form.requestSubmit(); })()"
    )


async def _result(page: Page, text: str) -> str:
    await page.wait_for(f"document.querySelector('#result').textContent.includes({text!r})")
    return await page.text("#result")


class TestTheLevelOfAnOutstation:
    @pytest.mark.asyncio
    async def test_the_add_form_offers_the_three_levels_and_sends_the_one_chosen(self, console):
        page = console.page
        options = "[...document.querySelector('#add-form').elements.level.options]"
        assert await page.evaluate(f"{options}.map((option) => option.value).join()") == "2,3,4"
        assert (
            await page.evaluate("document.querySelector('#add-form').elements.level.value") == "2"
        )
        await page.evaluate(
            "(() => { const form = document.querySelector('#add-form');"
            " form.elements.name.value = 'second'; form.elements.port.value = "
            f"{console.service.master['lab'].port}; form.elements.level.value = '4';"
            " form.requestSubmit(); })()"
        )
        await page.wait_for("state.outstations.some((each) => each.name === 'second')")
        assert console.service.master["second"].level == 4

    @pytest.mark.asyncio
    async def test_the_overview_and_the_page_say_what_level_the_outstation_is_held_to(
        self, console
    ):
        page = console.page
        assert "held to Level 2" in await page.text("#level-hint")
        await page.click(".tabs [data-tab='overview']")
        assert "Level 2" in await page.text("#overview-connection")

    @pytest.mark.asyncio
    @as_level
    async def test_the_hint_follows_the_level(self, console):
        assert "held to Level 3" in await console.page.text("#level-hint")


class TestReadByVariationOrRange:
    @pytest.mark.asyncio
    @as_level
    async def test_a_group_is_read_by_variation_and_range_and_the_answer_shown(self, console):
        page = console.page
        await page.evaluate(_fill("#group-form", group="30", variation="1", points="0-1"))
        assert await console.request() == "1e01000001"
        await _result(page, "READ")

    @pytest.mark.asyncio
    @as_level
    async def test_a_list_of_points_is_sent_as_indices_and_all_as_no_range(self, console):
        page = console.page
        await page.evaluate(_fill("#group-form", group="1", variation="2", points="0, 2"))
        # Level 3 reads by range and variation, and by list at Level 4: this is refused.
        await _result(page, "Level 4 request")
        assert console.frames_sent() == 0
        await page.evaluate(_fill("#group-form", group="30", variation="1", points=""))
        assert await console.request() == "1e0106"

    @pytest.mark.asyncio
    @at_level_2
    async def test_a_request_above_the_level_is_shown_as_refused_and_nothing_is_sent(self, console):
        page = console.page
        await page.evaluate(_fill("#group-form", group="30", variation="1", points="0-1"))
        shown = await _result(page, "Level 3 request")
        assert "set to Level 2" in shown
        assert await page.count("#result .error") == 1
        assert console.frames_sent() == 0

    @pytest.mark.asyncio
    @reading_at_4
    async def test_the_other_reads_send_their_requests(self, console):
        page = console.page
        for button, octets in (
            ("read_time", "32010701"),
            ("read_indications", "500100000f"),
            ("attributes_all", "00fe06"),
            ("attributes_list", "00ff06"),
            ("deadbands", "220006"),
        ):
            before = console.last
            await page.click(f"#level-reads [data-read='{button}']")
            assert await console.request(before) == octets, button


class TestWhatWrites:
    @pytest.mark.asyncio
    @reading_at_4
    async def test_the_controls_that_write_are_off_until_the_service_commands(self, console):
        page = console.page
        assert await page.evaluate("document.querySelector('#configure-fields').disabled") is True
        assert await page.evaluate("document.querySelector('#configure-off').hidden") is False
        assert "--allow-control" in await page.text("#configure-off")

    @pytest.mark.asyncio
    @commanding_at_4
    async def test_they_are_on_when_the_service_commands(self, console):
        page = console.page
        await page.wait_for("document.querySelector('#configure-fields').disabled === false")
        assert await page.evaluate("document.querySelector('#configure-off').hidden") is True

    @pytest.mark.asyncio
    @commanding_at_4
    async def test_events_are_assigned_to_a_class(self, console):
        page = console.page
        await page.wait_for("document.querySelector('#configure-fields').disabled === false")
        await page.evaluate(_fill("#assign-form", type="ai", indices="0, 1", event_class="2"))
        assert await console.request() == "3c03061e00000001"
        assert "ASSIGN_CLASS" in await _result(page, "ASSIGN_CLASS")

    @pytest.mark.asyncio
    @commanding_at_4
    async def test_events_are_turned_off_with_no_class(self, console):
        page = console.page
        await page.wait_for("document.querySelector('#configure-fields').disabled === false")
        await page.evaluate(_fill("#assign-form", type="bi", indices="all", event_class="0"))
        assert await console.request() == "3c0106010006"

    @pytest.mark.asyncio
    @commanding_at_4
    async def test_double_bit_inputs_are_assigned_by_group_3(self, console):
        page = console.page
        await page.wait_for("document.querySelector('#configure-fields').disabled === false")
        await page.evaluate(_fill("#assign-form", type="dbi", indices="2", event_class="1"))
        # Group 60 variation 2 (class 1), then g3v0 2..2.
        assert await console.request() == "3c02060300000202"

    @pytest.mark.asyncio
    @commanding_at_4
    async def test_a_deadband_is_written(self, console):
        page = console.page
        await page.wait_for("document.querySelector('#configure-fields').disabled === false")
        await page.evaluate(_fill("#deadband-form", index="4", value="25", variation="2"))
        assert await console.request() == "220200040419000000"

    @pytest.mark.asyncio
    @commanding_at_4
    async def test_a_text_attribute_is_sent_as_text_and_a_number_attribute_as_a_number(
        self, console
    ):
        page = console.page
        await page.wait_for("document.querySelector('#configure-fields').disabled === false")
        await page.evaluate(_fill("#attribute-form", variation="247", value="Inverter 4"))
        assert await console.request() == "00f7000000010a496e7665727465722034"
        before = console.last
        await page.evaluate(_fill("#attribute-form", variation="240", value="1500"))
        assert await console.request(before) == "00f00000000202dc05"


class TestWhatIsTyped:
    @pytest.mark.asyncio
    async def test_points_are_read_from_nothing_a_range_or_a_list(self, console):
        page = console.page
        script = "JSON.stringify(['', 'all', ' 4-8 ', '4, 6 8', '7'].map(pointsGiven))"
        assert await page.evaluate(script) == (
            '[{},{},{"start":4,"stop":8},{"indices":[4,6,8]},{"indices":[7]}]'
        )
