"""The console's DER tab, loaded in a real browser against the simulated DER.

The tab holds no logic: what it shows is the service's der.* operations, which
are tested at the service. What is tested here is the page: that the tab is
offered for an outstation with a profile, shows the nameplate, the functions
and the curve, switches a function when it may and not when it may not, and
shows the comparison with a Device Profile document. A machine with no
browser skips these; see ``browser.py``.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

import pytest
import pytest_asyncio
from browser import Page, open_page
from profile_fixtures import paired_reference_der

from py1815.master.service import HttpServer, Service
from py1815.profile import der, device_profile, load
from py1815.profile.model import Composition, Kind
from py1815.server import OutstationServer


@dataclass
class Console:
    page: Page
    service: Service
    simulation: der.Simulation


#: For a test of the tab over a service started to command.
commanding = pytest.mark.parametrize("console", [True], indirect=True)


@pytest_asyncio.fixture
async def console(request):
    """The console in a browser, on its DER tab, with the simulated DER added.

    Two analog inputs are named a nameplate, and the DER is given the Device
    Profile document it would publish.
    """
    point_map = load.resolve(paired_reference_der(), Composition())
    points = dict(point_map.points)
    for index, name in ((4, "Nameplate Active Power Rating"), (14, "Nameplate Apparent Power")):
        points[(Kind.AI, index)] = dataclasses.replace(
            points[(Kind.AI, index)], name=name, purpose="Nameplate", units="Watts"
        )
    point_map = dataclasses.replace(point_map, points=points)
    simulation = der.build(point_map)
    outstation = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    service = Service(allow_control=getattr(request, "param", False))
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
            await page.wait_for("document.querySelectorAll('.der-function').length > 0")
            yield Console(page, service, simulation)
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


def _switch(key: str) -> str:
    return f"document.querySelector(\".der-function[data-key='{key}'] input[role='switch']\")"


class TestTheTab:
    @pytest.mark.asyncio
    async def test_it_shows_the_nameplate_in_engineering_units(self, console):
        page = console.page
        await page.wait_for("document.querySelectorAll('#der-nameplate tbody tr').length === 2")
        first = await page.evaluate(
            "[...document.querySelector('#der-nameplate tbody tr').cells].map(c => c.textContent)"
        )
        watts = console.simulation.der.ratings.watts
        assert first == ["AI4", "Nameplate Active Power Rating", f"{watts:g} Watts", "ONLINE"]
        assert page.errors == []

    @pytest.mark.asyncio
    async def test_it_lists_the_supported_functions_and_names_the_rest(self, console):
        page = console.page
        keys = await page.evaluate(
            "[...document.querySelectorAll('.der-function')].map(row => row.dataset.key)"
        )
        assert set(keys) == {
            function.name.replace("/", "-").replace(" ", "-") for function in der.FUNCTIONS
        }
        assert "Not supported: unimplemented" in await page.text(".der-unsupported")

    @pytest.mark.asyncio
    async def test_a_functions_settings_are_read_when_shown(self, console):
        page = console.page
        await page.click(".der-function[data-key='volt-var'] button")
        await page.wait_for(
            "document.querySelectorAll(\".der-function[data-key='volt-var'] tbody tr\").length > 5"
        )
        rows = await page.text(".der-function[data-key='volt-var'] tbody")
        assert f"AO{der.AO_VOLT_VAR_FIRST}" in rows
        # Disabled, the function's inputs travel without ONLINE.
        assert "OFFLINE" in rows

    @pytest.mark.asyncio
    async def test_the_curve_the_block_shows_is_plotted_and_tabled(self, console):
        page = console.page
        written = await console.service.handle(
            {
                "op": "der.write_curve",
                "outstation": "lab",
                "params": {
                    "number": 1,
                    "type": 2,
                    "x_units": 129,
                    "y_units": 2,
                    "points": [[920, 300], [1080, -300]],
                },
            }
        )
        # A service that only reads refuses to write the curve; the simulated
        # DER is given it directly instead.
        assert written["error"]["kind"] == "not_allowed"
        curve = console.simulation.der.curves.curves[1]
        curve.fields[:] = [2.0, 2.0, 129.0, 2.0]
        curve.values[:4] = [920.0, 300.0, 1080.0, -300.0]
        await page.click("#der-reload")
        await page.wait_for("document.querySelectorAll('#der-curve-points tbody tr').length === 2")
        assert await page.count("#der-curve svg polyline") == 1
        assert await page.count("#der-curve svg circle") == 2
        assert await page.evaluate(
            "[...document.querySelectorAll('#der-curve-points tbody tr')].map(r => r.textContent)"
        ) == ["1920300", "21080-300"]

    @pytest.mark.asyncio
    async def test_the_comparison_with_the_device_profile_says_what_differs(self, console):
        page = console.page
        await page.click("#der-compare")
        await page.wait_for("document.querySelector('.der-summary') !== null")
        summary = await page.text(".der-summary")
        assert "Declared and absent0" in summary.replace("\n", "")
        assert "Served and undeclared0" in summary.replace("\n", "")

    @pytest.mark.asyncio
    async def test_it_asks_the_outside_world_for_nothing(self, console):
        own = (await console.page.evaluate("location.origin")).rstrip("/")
        assert [url for url in console.page.requests if not url.startswith(own)] == []


class TestReadOnly:
    @pytest.mark.asyncio
    async def test_the_switches_and_the_settings_form_are_disabled(self, console):
        page = console.page
        switch = _switch("volt-var")
        assert await page.evaluate(f"{switch}.disabled")
        assert "--allow-control" in await page.text("#der-functions")
        await page.click(".der-function[data-key='volt-var'] button")
        await page.wait_for('document.querySelector(".der-write fieldset") !== null')
        assert await page.evaluate("document.querySelector('.der-write fieldset').disabled")
        assert await page.evaluate("document.querySelector('#der-curve-form fieldset').disabled")

    @pytest.mark.asyncio
    async def test_the_service_refuses_even_if_the_page_is_made_to_switch(self, console):
        page = console.page
        switch = _switch("volt-var")
        await page.evaluate(f"{switch}.disabled = false; {switch}.click()")
        await page.click(".tabs [data-tab='log']")
        await page.wait_for(
            "document.querySelector('#log').textContent.includes('enable volt-var failed')"
        )
        assert console.simulation.der.settings[(Kind.BO, der.BO_ENABLE_VOLT_VAR)] is False


@commanding
class TestCommanding:
    @pytest.mark.asyncio
    async def test_a_function_is_enabled_by_its_switch_and_read_back(self, console):
        page = console.page
        switch = _switch("volt-var")
        assert not await page.evaluate(f"{switch}.disabled")
        await page.evaluate(f"{switch}.click()")
        await page.wait_for(
            "document.querySelector(\".der-function[data-key='volt-var'] .der-state\")"
            ".textContent === 'Enabled'"
        )
        assert console.simulation.der.settings[(Kind.BO, der.BO_ENABLE_VOLT_VAR)] is True
        assert await page.evaluate(f"{_switch('volt-var')}.checked")

    @pytest.mark.asyncio
    async def test_a_setting_is_written_by_name_and_read_back(self, console):
        page = console.page
        await page.click(".der-function[data-key='active-power-limit'] button")
        await page.wait_for("document.querySelector('.der-write fieldset') !== null")
        await page.evaluate(
            "(() => { const form = document.querySelector("
            "\".der-write[data-function='active-power-limit']\");"
            f" form.elements.point.value = 'AO{der.AO_POWER_LIMIT_GENERATION}';"
            " form.elements.value.value = '40'; form.requestSubmit(); })()"
        )
        await page.wait_for("document.querySelector('.der-written .verdict') !== null")
        assert await page.text(".der-written .verdict") == "Accepted"
        assert "read back the same" in await page.text(".der-written")
        assert console.simulation.outstation.value(Kind.AO, der.AO_POWER_LIMIT_GENERATION) == 40
