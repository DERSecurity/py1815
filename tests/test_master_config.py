"""Tests for the master's JSON configuration and the command line that loads it."""

from __future__ import annotations

import json
import pathlib

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der

from py1815.master import cli
from py1815.master.config import ConfigError, MasterConfig, OutstationConfig
from py1815.master.service import Service
from py1815.master.tasks import Tasks
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

ALL_TASKS = {
    "startup": True,
    "clear_restart": True,
    "write_time": True,
    "enable_unsolicited": [],
    "events_when_indicated": True,
    "integrity_on_overflow": True,
}


def _args(*arguments: str):
    return cli._parser().parse_args(list(arguments))


def _file(tmp_path, document) -> str:
    path = tmp_path / "master.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


class TestDefaults:
    def test_empty_document_gives_the_documented_defaults(self):
        config = MasterConfig.from_mapping({})
        assert config.describe() == {
            "allow_control": False,
            "bind": None,
            "tables": None,
            "connect_wait": 0.0,
            "defaults": {
                "port": 20000,
                "outstation_address": 1024,
                "master_address": 1,
                "response_timeout": 5.0,
                "connect_timeout": 5.0,
                "connect": True,
                "reconnect": 5.0,
                "confirm": True,
                "manual": False,
                "profile": False,
                "device_profile": None,
                "tasks": ALL_TASKS,
                "repeat": {"integrity": None, "events": None, "outputs": "with_integrity"},
            },
            "outstations": [],
        }

    def test_defaults_match_the_python_api(self):
        defaults = OutstationConfig()
        assert defaults.tasks == Tasks()
        assert defaults.reconnect == 5.0


DOCUMENTED = pathlib.Path(__file__).parent.parent / "docs" / "master-config.md"


@pytest.mark.skipif(not DOCUMENTED.is_file(), reason="the documentation is not beside the tests")
def test_documented_example_is_valid_and_shows_the_real_defaults():
    text = DOCUMENTED.read_text(encoding="utf-8")
    document = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
    config = MasterConfig.from_mapping(document)
    real = MasterConfig.from_mapping({}).describe()
    for key in ("allow_control", "bind", "tables", "connect_wait", "defaults"):
        assert document[key] == real[key], key
    assert [each.name for each in config.outstations] == ["lab", "bench"]


class TestOutstations:
    def test_outstation_inherits_defaults_and_overrides_them(self):
        config = MasterConfig.from_mapping(
            {
                "defaults": {"reconnect": 2, "tasks": {"write_time": False}},
                "outstations": [
                    {"name": "a", "host": "10.0.0.1"},
                    {"name": "b", "host": "10.0.0.2", "port": 20001, "reconnect": None},
                ],
            }
        )
        first, second = config.outstations
        assert (first.port, first.reconnect, first.tasks.write_time) == (20000, 2.0, False)
        assert (second.port, second.reconnect, second.tasks.write_time) == (20001, None, False)

    def test_tasks_and_repeat_are_merged_not_replaced(self):
        config = MasterConfig.from_mapping(
            {
                "defaults": {
                    "tasks": {"enable_unsolicited": [1, 2]},
                    "repeat": {"integrity": 30, "events": 2},
                },
                "outstations": [
                    {
                        "name": "a",
                        "host": "h",
                        "tasks": {"startup": False},
                        "repeat": {"events": None},
                    }
                ],
            }
        )
        (outstation,) = config.outstations
        assert outstation.tasks.enable_unsolicited == (1, 2) and not outstation.tasks.startup
        assert outstation.repeat == {"integrity": 30.0, "events": None, "outputs": "with_integrity"}

    def test_describe_lists_only_what_differs_from_the_defaults(self):
        document = {
            "defaults": {"repeat": {"integrity": 30}},
            "outstations": [
                {"name": "a", "host": "h"},
                {"name": "b", "host": "h", "manual": True, "tasks": {"startup": False}},
            ],
        }
        described = MasterConfig.from_mapping(document).describe()
        assert described["outstations"] == [
            {"name": "a", "host": "h"},
            {"name": "b", "host": "h", "manual": True, "tasks": {"startup": False}},
        ]

    def test_printed_configuration_loads_back_unchanged(self):
        config = MasterConfig.from_mapping(
            {
                "allow_control": True,
                "bind": "127.0.0.1:9000",
                "connect_wait": 10,
                "defaults": {"repeat": {"integrity": 30, "outputs": None}, "profile": True},
                "outstations": [{"name": "a", "host": "h", "tasks": {"enable_unsolicited": [3]}}],
            }
        )
        assert MasterConfig.from_mapping(json.loads(config.render())) == config


class TestAddParams:
    def test_repeat_becomes_the_three_intervals(self):
        outstation = OutstationConfig().changed(
            {"name": "a", "host": "h", "repeat": {"integrity": 30, "events": 2}}, "o"
        )
        params = outstation.add_params(allow_control=True)
        assert (params["integrity_interval"], params["event_interval"]) == (30.0, 2.0)
        assert params["output_interval"] == 30.0, "outputs follow the integrity poll"

    @pytest.mark.parametrize("outputs, expected", [(None, None), (5, 5.0)])
    def test_output_interval_can_be_set_or_turned_off(self, outputs, expected):
        outstation = OutstationConfig().changed(
            {"name": "a", "host": "h", "repeat": {"integrity": 30, "outputs": outputs}}, "o"
        )
        assert outstation.add_params(allow_control=True)["output_interval"] == expected

    def test_read_only_leaves_the_writing_tasks_to_the_service(self):
        outstation = OutstationConfig().changed({"name": "a", "host": "h"}, "o")
        commanding = outstation.add_params(allow_control=True)["tasks"]
        reading = outstation.add_params(allow_control=False)["tasks"]
        assert commanding == ALL_TASKS
        writing = ("clear_restart", "write_time")
        assert reading == {k: v for k, v in ALL_TASKS.items() if k not in writing}

    def test_manual_overrides_tasks_and_confirm(self):
        outstation = OutstationConfig().changed({"name": "a", "host": "h", "manual": True}, "o")
        params = outstation.add_params(allow_control=True)
        assert params["manual"] is True and "tasks" not in params and "confirm" not in params


class TestErrors:
    @pytest.mark.parametrize(
        "document, says",
        [
            ({"allow_controls": True}, "configuration.allow_controls is not a setting"),
            ({"allow_control": "yes"}, "allow_control must be true or false"),
            ({"connect_wait": -1}, "connect_wait must be a number of seconds, zero or more"),
            ({"bind": 8815}, "bind must be a non-empty string"),
            ({"outstations": {"name": "a"}}, "outstations must be a list"),
            ({"outstations": [{"host": "h"}]}, "outstations[0].name is required"),
            ({"outstations": [{"name": "a"}]}, "outstations[0].host is required"),
            (
                {"outstations": [{"name": "a", "host": "h"}, {"name": "a", "host": "i"}]},
                "outstations[1].name 'a' is used more than once",
            ),
            ({"defaults": {"name": "a"}}, "defaults.name belongs in an outstation's own entry"),
            ({"defaults": {"prot": 1}}, "defaults.prot is not a setting"),
            ({"defaults": {"port": 0}}, "defaults.port must be a whole number from 1 to 65535"),
            ({"defaults": {"port": True}}, "defaults.port must be a whole number"),
            ({"defaults": {"outstation_address": 65520}}, "from 0 to 65519"),
            ({"defaults": {"master_address": 1024}}, "must be different"),
            ({"defaults": {"response_timeout": 0}}, "defaults.response_timeout must be greater"),
            ({"defaults": {"reconnect": "5"}}, "defaults.reconnect must be a number of seconds"),
            ({"defaults": {"reconnect": float("inf")}}, "defaults.reconnect must be a finite"),
            ({"defaults": {"response_timeout": float("nan")}}, "must be a finite"),
            ({"connect_wait": float("inf")}, "connect_wait must be a number of seconds"),
            ({"defaults": {"tasks": {"enable_unsolicited": [1.9]}}}, "defaults.tasks:"),
            ({"defaults": {"tasks": {"enable_unsolicited": [None]}}}, "defaults.tasks:"),
            ({"defaults": {"manual": 1}}, "defaults.manual must be true or false"),
            ({"defaults": {"tasks": []}}, "defaults.tasks must be an object"),
            ({"defaults": {"tasks": {"polling": True}}}, "defaults.tasks: 'polling' is not a task"),
            ({"defaults": {"tasks": {"enable_unsolicited": [4]}}}, "defaults.tasks:"),
            ({"defaults": {"repeat": {"class1": 5}}}, "defaults.repeat.class1 is not a setting"),
            ({"defaults": {"repeat": {"events": 0}}}, "defaults.repeat.events must be greater"),
            (
                {"defaults": {"repeat": {"integrity": "with_integrity"}}},
                "defaults.repeat.integrity must be a number",
            ),
            (
                {"outstations": [{"name": "a", "host": "h", "tasks": {"startup": "no"}}]},
                "outstations[0].tasks: startup is true or false",
            ),
        ],
    )
    def test_mistakes_are_reported_with_their_location(self, document, says):
        with pytest.raises(ConfigError) as raised:
            MasterConfig.from_mapping(document)
        assert says in str(raised.value)

    def test_missing_file_and_bad_json_are_reported(self, tmp_path):
        with pytest.raises(ConfigError, match="none"):
            MasterConfig.load(tmp_path / "none.json")
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with pytest.raises(ConfigError, match="is not valid JSON"):
            MasterConfig.load(broken)
        listed = tmp_path / "list.json"
        listed.write_text("[]", encoding="utf-8")
        with pytest.raises(ConfigError, match="must hold a JSON object"):
            MasterConfig.load(listed)


class TestCommandLine:
    def test_flags_alone_build_the_configuration(self):
        config = cli.configuration(
            _args(
                "serve",
                "--allow-control",
                "--bind",
                "127.0.0.1:9001",
                "--outstation",
                "lab=10.0.0.5:20001",
                "--outstation-address",
                "10",
                "--master-address",
                "3",
                "--integrity-interval",
                "30",
                "--event-interval",
                "2",
                "--output-interval",
                "0",
                "--unsolicited",
                "1,2",
                "--reconnect",
                "1.5",
                "--connect-wait",
                "20",
                "--profile",
            )
        )
        (lab,) = config.outstations
        assert (config.allow_control, config.bind, config.connect_wait) == (
            True,
            "127.0.0.1:9001",
            20.0,
        )
        assert (lab.name, lab.host, lab.port) == ("lab", "10.0.0.5", 20001)
        assert (lab.outstation_address, lab.master_address) == (10, 3)
        assert lab.repeat == {"integrity": 30.0, "events": 2.0, "outputs": None}
        assert lab.tasks.enable_unsolicited == (1, 2) and lab.reconnect == 1.5 and lab.profile

    def test_file_is_used_when_no_flag_overrides_it(self, tmp_path):
        path = _file(
            tmp_path,
            {
                "allow_control": True,
                "bind": "127.0.0.1:9002",
                "defaults": {"reconnect": None, "repeat": {"integrity": 60}},
                "outstations": [{"name": "a", "host": "10.0.0.1", "manual": True}],
            },
        )
        config = cli.configuration(_args("console", "--config", path))
        (outstation,) = config.outstations
        assert config.allow_control and config.bind == "127.0.0.1:9002"
        assert outstation.manual and outstation.reconnect is None
        assert outstation.repeat["integrity"] == 60.0

    def test_flags_override_the_file(self, tmp_path):
        path = _file(
            tmp_path,
            {
                "bind": "127.0.0.1:9002",
                "connect_wait": 5,
                "defaults": {
                    "reconnect": None,
                    "repeat": {"integrity": 60, "events": 9},
                    "tasks": {"startup": False},
                },
                "outstations": [{"name": "a", "host": "10.0.0.1"}],
            },
        )
        config = cli.configuration(
            _args(
                "console",
                "--config",
                path,
                "--bind",
                "127.0.0.1:9003",
                "--connect-wait",
                "0",
                "--reconnect",
                "3",
                "--integrity-interval",
                "10",
                "--unsolicited",
                "3",
                "--allow-control",
            )
        )
        (outstation,) = config.outstations
        assert (config.bind, config.connect_wait, config.allow_control) == (
            "127.0.0.1:9003",
            0.0,
            True,
        )
        assert outstation.reconnect == 3.0
        # Only what the flags name changes: the rest of the file's settings stay.
        assert outstation.repeat == {"integrity": 10.0, "events": 9.0, "outputs": "with_integrity"}
        assert outstation.tasks.enable_unsolicited == (3,) and not outstation.tasks.startup

    def test_an_outstation_entry_keeps_its_own_setting_over_a_flag(self, tmp_path):
        path = _file(
            tmp_path, {"outstations": [{"name": "a", "host": "h", "reconnect": 9, "manual": False}]}
        )
        config = cli.configuration(_args("serve", "--config", path, "--reconnect", "1"))
        assert config.outstations[0].reconnect == 9.0
        assert config.defaults.reconnect == 1.0

    def test_outstations_on_the_command_line_are_added_to_the_file(self, tmp_path):
        path = _file(tmp_path, {"outstations": [{"name": "a", "host": "h"}]})
        config = cli.configuration(_args("serve", "--config", path, "--outstation", "b=i:20001"))
        assert [(each.name, each.host, each.port) for each in config.outstations] == [
            ("a", "h", 20000),
            ("b", "i", 20001),
        ]
        with pytest.raises(ConfigError, match="used more than once"):
            cli.configuration(_args("serve", "--config", path, "--outstation", "a=i:20001"))

    def test_config_command_prints_a_file_that_loads_back(self, tmp_path, capsys):
        assert cli.main(["config", "--outstation", "lab=10.0.0.5:20000", "--unsolicited", "2"]) == 0
        printed = capsys.readouterr().out
        document = json.loads(printed)
        assert document["defaults"]["tasks"]["enable_unsolicited"] == [2]
        assert document["outstations"] == [{"name": "lab", "host": "10.0.0.5"}]

        path = tmp_path / "written.json"
        assert cli.main(["config", "--out", str(path), "--outstation", "lab=10.0.0.5:20000"]) == 0
        assert "wrote" in capsys.readouterr().out
        assert cli.main(["config", "--config", str(path)]) == 0
        assert json.loads(capsys.readouterr().out) == json.loads(path.read_text(encoding="utf-8"))

    @pytest.mark.parametrize("command", ["console", "serve", "config"])
    def test_a_bad_file_stops_every_command_with_its_message(self, command, tmp_path, capsys):
        path = _file(tmp_path, {"defaults": {"prot": 20000}})
        assert cli.main([command, "--config", path]) == 2
        assert "defaults.prot is not a setting" in capsys.readouterr().err


@pytest_asyncio.fixture
async def outstation():
    simulation = der.build(load.resolve(for_reference_der(), Composition()))
    server = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    await server.start()
    try:
        yield server
    finally:
        await server.stop()


class TestAppliedToTheService:
    """The settings in a file reach the outstation the service adds."""

    async def _status(self, config: MasterConfig) -> dict:
        service = Service(allow_control=config.allow_control)
        try:
            assert await cli._add_outstations(service, config)
            await service.handle({"op": "idle", "outstation": "lab"})
            (lab,) = (await service.handle({"op": "status"}))["result"]["outstations"]
            return lab
        finally:
            await service.close()

    @pytest.mark.asyncio
    async def test_every_setting_is_applied(self, outstation, tmp_path):
        path = _file(
            tmp_path,
            {
                "allow_control": True,
                "defaults": {
                    "reconnect": 2.5,
                    "tasks": {"write_time": False, "events_when_indicated": False},
                    "repeat": {"integrity": 60, "events": 7, "outputs": 9},
                },
                "outstations": [{"name": "lab", "host": "127.0.0.1", "port": outstation.port}],
            },
        )
        lab = await self._status(cli.configuration(_args("serve", "--config", path)))
        assert lab["connected"] and lab["reconnect"] == 2.5
        assert lab["repeat"] == {"integrity": 60.0, "events": 7.0, "outputs": 9.0}
        assert lab["tasks"] == ALL_TASKS | {"write_time": False, "events_when_indicated": False}
        # The restart was cleared and the time was not written.
        assert "DEVICE_RESTART" not in lab["indications"] and "NEED_TIME" in lab["indications"]

    @pytest.mark.asyncio
    async def test_read_only_file_with_default_tasks_is_accepted(self, outstation, tmp_path):
        """A printed file lists the writing tasks as on. Read-only must not refuse it."""
        printed = MasterConfig.from_mapping(
            {"outstations": [{"name": "lab", "host": "127.0.0.1", "port": outstation.port}]}
        ).render()
        path = tmp_path / "printed.json"
        path.write_text(printed, encoding="utf-8")
        lab = await self._status(cli.configuration(_args("serve", "--config", str(path))))
        assert lab["connected"]
        assert not lab["tasks"]["clear_restart"] and not lab["tasks"]["write_time"]
        assert "DEVICE_RESTART" in lab["indications"]

    @pytest.mark.asyncio
    async def test_manual_in_a_file_sends_nothing(self, outstation, tmp_path):
        path = _file(
            tmp_path,
            {
                "allow_control": True,
                "outstations": [
                    {"name": "lab", "host": "127.0.0.1", "port": outstation.port, "manual": True}
                ],
            },
        )
        lab = await self._status(cli.configuration(_args("serve", "--config", path)))
        assert lab["connected"] and lab["counts"] == {} and not any(lab["tasks"].values())
