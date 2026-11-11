"""Tests for the DER outstation's JSON configuration and the command line that loads it."""

from __future__ import annotations

import asyncio
import json
import pathlib

import pytest
from profile_fixtures import for_reference_der

from py1815.application import FunctionCode
from py1815.master import Loopback, Master, PointType
from py1815.profile import cli, der, load
from py1815.profile.config import DerConfig, Identity
from py1815.profile.model import Composition
from py1815.settings import ConfigError

DEFAULTS = {
    "bind": "127.0.0.1:20000",
    "tables": None,
    "outstation_address": 1024,
    "master_address": 1,
    "unsolicited": False,
    "read_only": False,
    "level": None,
    "disabled_offline": True,
    "event_capacity": 2000,
    "max_response": 2048,
    "timing_accuracy_us": 1000000,
    "select_timeout": 10.0,
    "confirm_timeout": 10.0,
    "idle_timeout": 300.0,
    "event_policy": None,
    "composition": {"meters": 0, "der_units": 0, "inverters": 0, "batteries": 0},
    "simulation": {"seed": 0, "tick": 1.0},
    "identity": {
        "vendor": "Not stated",
        "device": "py1815 simulated DER outstation",
        "hardware_version": "Not applicable (software)",
        "software_version": "",
        "author": "py1815",
        "serial_number": "",
        "location_name": "",
        "device_id": "",
        "device_name": "",
    },
}

DOCUMENTED = pathlib.Path(__file__).parent.parent / "docs" / "der-config.md"


def _args(*arguments: str):
    return cli._parser().parse_args(list(arguments))


def _file(tmp_path, document) -> str:
    path = tmp_path / "der.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


@pytest.fixture
def tables(tmp_path, monkeypatch):
    """The reference tables, where the command line looks for them."""
    path = tmp_path / load.TABLES_NAME
    path.write_text(json.dumps(for_reference_der()), encoding="utf-8")
    monkeypatch.setenv(load.TABLES_VARIABLE, str(path))
    return path


class TestDefaults:
    def test_empty_document_gives_the_documented_defaults(self):
        assert DerConfig.from_mapping({}).describe() == DEFAULTS

    def test_printed_configuration_loads_back_unchanged(self):
        config = DerConfig.from_mapping(
            {
                "bind": "0.0.0.0:20001",
                "master_address": None,
                "read_only": True,
                "confirm_timeout": None,
                "event_policy": {"defaults": {"AI": {"class": 2, "deadband": 0.5}}},
                "composition": {"meters": 1},
                "simulation": {"seed": 7},
                "identity": {"vendor": "Example"},
            }
        )
        assert DerConfig.from_mapping(json.loads(config.render())) == config
        assert config.composition == Composition(meters=1)
        assert (config.seed, config.tick) == (7, 1.0)
        assert config.identity == Identity(vendor="Example")

    @pytest.mark.skipif(
        not DOCUMENTED.is_file(), reason="the documentation is not beside the tests"
    )
    def test_documented_example_shows_the_real_defaults(self):
        text = DOCUMENTED.read_text(encoding="utf-8")
        document = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
        assert document == DEFAULTS


class TestErrors:
    @pytest.mark.parametrize(
        "document, says",
        [
            ({"bnid": "x"}, "configuration.bnid is not a setting"),
            ({"bind": ""}, "bind must be a non-empty string"),
            ({"outstation_address": 70000}, "outstation_address must be a whole number from 0"),
            ({"master_address": 1024}, "outstation_address and master_address must be different"),
            ({"unsolicited": "yes"}, "unsolicited must be true or false"),
            ({"read_only": 1}, "read_only must be true or false"),
            ({"event_capacity": 0}, "event_capacity must be a whole number from 1"),
            ({"max_response": 100}, "max_response must be a whole number from 249"),
            ({"select_timeout": 0}, "select_timeout must be greater than 0"),
            ({"select_timeout": float("inf")}, "select_timeout must be a finite number"),
            ({"simulation": {"tick": float("inf")}}, "simulation.tick must be a finite number"),
            ({"idle_timeout": float("nan")}, "idle_timeout must be a finite number"),
            (
                {"unsolicited": True, "confirm_timeout": None},
                "confirm_timeout must be a number of seconds when unsolicited is true",
            ),
            ({"idle_timeout": "long"}, "idle_timeout must be a number of seconds"),
            ({"composition": {"meter": 1}}, "composition.meter is not a setting"),
            ({"composition": {"meters": -1}}, "composition.meters must be a whole number from 0"),
            ({"composition": []}, "composition must be an object"),
            ({"simulation": {"tick": 0}}, "simulation.tick must be greater than 0"),
            ({"simulation": {"speed": 2}}, "simulation.speed is not a setting"),
            ({"seed": 3}, "configuration.seed is not a setting"),
            ({"identity": {"vendor": 5}}, "identity.vendor must be a string"),
            ({"identity": {"maker": "x"}}, "identity.maker is not a setting"),
            ({"event_policy": []}, "event_policy must be an object or null"),
            ({"event_policy": {"rules": {}}}, "event_policy:"),
            ({"event_policy": {"defaults": {"AO": {"class": 1}}}}, "event_policy:"),
        ],
    )
    def test_mistakes_are_reported_with_their_location(self, document, says):
        with pytest.raises(ConfigError) as raised:
            DerConfig.from_mapping(document)
        assert says in str(raised.value)

    def test_infinity_written_in_json_is_rejected(self, tmp_path):
        """JSON has no infinity, but 1e309 decodes to one."""
        path = tmp_path / "der.json"
        path.write_text('{"simulation": {"tick": 1e309}}', encoding="utf-8")
        with pytest.raises(ConfigError, match="tick must be a finite number"):
            DerConfig.load(path)

    def test_no_confirm_timeout_is_allowed_without_unsolicited(self):
        config = DerConfig.from_mapping({"confirm_timeout": None})
        assert config.confirm_timeout is None and not config.unsolicited

    def test_every_accepted_configuration_builds_a_session(self):
        """The check command must not accept what `run` would then refuse."""
        for document in ({}, {"unsolicited": True}, {"confirm_timeout": None}):
            config = DerConfig.from_mapping(document)
            point_map = load.resolve(for_reference_der(), config.composition)
            simulation = der.build(point_map, seed=config.seed, **config.outstation_options())
            simulation.outstation.session(**config.session_options())

    def test_missing_file_is_reported(self, tmp_path):
        with pytest.raises(ConfigError, match="none"):
            DerConfig.load(tmp_path / "none.json")


class TestDeviceAttributes:
    def test_level_4_reports_the_identity_and_accuracy_as_device_attributes(self):
        config = DerConfig.from_mapping(
            {
                "level": 4,
                "timing_accuracy_us": 2000,
                "identity": {
                    "vendor": "Acme",
                    "device": "Widget 9",
                    "software_version": "1.2.3",
                    "hardware_version": "Rev D",
                    "serial_number": "SN-1",
                    "location_name": "Plant 4",
                },
            }
        )
        point_map = load.resolve(for_reference_der(), config.composition)
        built = der.build(point_map, **config.outstation_options())
        view = built.outstation.attributes.snapshot()
        values = {number: attribute.value for number, attribute in view.items()}
        assert {
            number: values[number] for number in (252, 250, 242, 243, 248, 245, 246, 217, 249)
        } == {
            252: "Acme",
            250: "Widget 9",
            242: "1.2.3",
            243: "Rev D",
            248: "SN-1",
            245: "Plant 4",
            246: "",
            217: 2000,
            249: "4:",
        }

    def test_below_level_4_the_identity_is_not_held_to_ascii(self):
        config = DerConfig.from_mapping({"level": 3, "identity": {"vendor": "Müller"}})
        assert config.outstation_options()["information"] is None
        simulation = der.build(
            load.resolve(for_reference_der(), config.composition), **config.outstation_options()
        )
        assert simulation.outstation.attributes is None

    @pytest.mark.parametrize("name", ["vendor", "device", "serial_number", "device_name"])
    def test_at_level_4_a_text_that_is_not_visible_ascii_names_its_setting(self, name):
        with pytest.raises(ConfigError, match=rf"identity\.{name}: text of at most 128"):
            DerConfig.from_mapping({"level": 4, "identity": {name: "café"}})

    @pytest.mark.parametrize("value", [-1, 2**32, 1.5, "1", True])
    def test_the_timing_accuracy_is_an_unsigned_32_bit_whole_number(self, value):
        with pytest.raises(ConfigError, match="timing_accuracy_us must be a whole number from 0"):
            DerConfig.from_mapping({"timing_accuracy_us": value})


class TestCommandLine:
    def test_flags_alone_build_the_configuration(self):
        config = cli.configuration(
            _args(
                "run",
                "--bind",
                "0.0.0.0:20005",
                "--outstation-address",
                "10",
                "--master-address",
                "3",
                "--unsolicited",
                "--read-only",
                "--level",
                "3",
                "--event-capacity",
                "500",
                "--max-response",
                "4096",
                "--select-timeout",
                "5",
                "--idle-timeout",
                "60",
                "--meters",
                "1",
                "--inverters",
                "2",
                "--seed",
                "9",
                "--tick",
                "0.5",
            )
        )
        assert config.describe() == DEFAULTS | {
            "bind": "0.0.0.0:20005",
            "outstation_address": 10,
            "master_address": 3,
            "unsolicited": True,
            "read_only": True,
            "level": 3,
            "event_capacity": 500,
            "max_response": 4096,
            "select_timeout": 5.0,
            "idle_timeout": 60.0,
            "composition": DEFAULTS["composition"] | {"meters": 1, "inverters": 2},
            "simulation": {"seed": 9, "tick": 0.5},
        }

    def test_the_device_attribute_flags_set_the_identity_and_the_timing_accuracy(self):
        config = cli.configuration(
            _args(
                "run",
                "--level",
                "4",
                "--vendor",
                "Acme",
                "--serial-number",
                "SN-1",
                "--location-name",
                "Plant 4",
                "--device-id",
                "ID-7",
                "--device-name",
                "Unit A",
                "--timing-accuracy-us",
                "2000",
            )
        )
        assert config.identity == Identity(
            vendor="Acme",
            serial_number="SN-1",
            location_name="Plant 4",
            device_id="ID-7",
            device_name="Unit A",
        )
        assert config.timing_accuracy_us == 2000

    def test_any_master_clears_the_master_address(self):
        assert cli.configuration(_args("run", "--any-master")).master_address is None

    def test_file_is_used_when_no_flag_overrides_it(self, tmp_path):
        document = {
            "bind": "0.0.0.0:20001",
            "unsolicited": True,
            "composition": {"meters": 2, "batteries": 1},
            "simulation": {"seed": 4, "tick": 2},
            "identity": {"vendor": "Example", "device": "Unit"},
        }
        config = cli.configuration(_args("run", "--config", _file(tmp_path, document)))
        assert config.bind == "0.0.0.0:20001" and config.unsolicited
        assert config.composition == Composition(meters=2, batteries=1)
        assert (config.seed, config.tick) == (4, 2.0)
        assert config.identity.vendor == "Example"

    def test_flags_override_the_file_and_leave_the_rest(self, tmp_path):
        path = _file(
            tmp_path,
            {
                "bind": "0.0.0.0:20001",
                "master_address": 5,
                "composition": {"meters": 2, "batteries": 1},
                "simulation": {"seed": 4, "tick": 2},
                "identity": {"vendor": "Example", "device": "Unit"},
            },
        )
        config = cli.configuration(
            _args(
                "profile",
                "--config",
                path,
                "--bind",
                "127.0.0.1:20002",
                "--meters",
                "3",
                "--seed",
                "8",
                "--vendor",
                "Other",
            )
        )
        assert config.bind == "127.0.0.1:20002" and config.master_address == 5
        assert config.composition == Composition(meters=3, batteries=1)
        assert (config.seed, config.tick) == (8, 2.0)
        assert (config.identity.vendor, config.identity.device) == ("Other", "Unit")

    def test_config_command_prints_a_file_that_loads_back(self, tmp_path, capsys):
        assert cli.main(["config", "--meters", "1", "--read-only"]) == 0
        document = json.loads(capsys.readouterr().out)
        assert document["read_only"] is True and document["composition"]["meters"] == 1

        path = tmp_path / "written.json"
        assert cli.main(["config", "--out", str(path), "--unsolicited"]) == 0
        assert "wrote" in capsys.readouterr().out
        assert cli.main(["config", "--config", str(path)]) == 0
        assert json.loads(capsys.readouterr().out) == json.loads(path.read_text(encoding="utf-8"))

    @pytest.mark.parametrize("command", ["run", "points", "profile", "config"])
    def test_a_bad_file_stops_every_command_with_its_message(self, command, tmp_path, capsys):
        path = _file(tmp_path, {"read_only": "yes"})
        assert cli.main([command, "--config", path]) == 2
        assert "read_only must be true or false" in capsys.readouterr().err

    def test_poll_keeps_its_own_address_defaults(self):
        args = _args("poll")
        assert (args.outstation_address, args.master_address) == (1024, 1)


class TestAppliedToTheOutstation:
    """The settings in a file reach the outstation that is served."""

    def _simulation(self, document) -> tuple[DerConfig, der.Simulation]:
        config = DerConfig.from_mapping(document)
        point_map = load.resolve(for_reference_der(), config.composition)
        return config, der.build(point_map, seed=config.seed, **config.outstation_options())

    def test_read_only_refuses_controls(self):
        config, simulation = self._simulation({"read_only": True})
        master = Loopback(simulation.outstation.session(**config.session_options()))
        result = master.operate(analog_outputs={der.AO_POWER_LIMIT_GENERATION: 300})
        assert result.accepted is False
        assert result.statuses[0].status.name == "NOT_AUTHORIZED"

    def test_addresses_and_unsolicited_reach_the_session(self):
        config, simulation = self._simulation(
            {"outstation_address": 10, "master_address": 3, "unsolicited": True}
        )
        session = simulation.outstation.session(**config.session_options())
        facts = session.facts
        assert (facts.outstation_address, facts.master_address) == (10, 3)
        master = Loopback(session)
        enabled = master.enable_unsolicited(1)
        assert enabled.function is FunctionCode.ENABLE_UNSOLICITED and enabled.iin.second == 0

    def test_any_master_serves_whoever_speaks_first(self):
        config, simulation = self._simulation({"master_address": None})
        session = simulation.outstation.session(**config.session_options())
        assert session.facts.master_address is None

    def test_event_capacity_and_policy_reach_the_outstation(self):
        config, simulation = self._simulation(
            {"event_capacity": 7, "event_policy": {"defaults": {"AI": {"events": False}}}}
        )
        outstation = simulation.outstation
        assert outstation.events.capacity == 7
        simulation.advance(5.0)
        simulation.advance(5.0)
        master = Loopback(outstation.session(**config.session_options()))
        events = master.scan("events")
        assert not any(decoded.point.value == "ai" for decoded in events.objects)

    @pytest.mark.parametrize("level, variation", [(None, 1), (2, 2), (3, 1), (4, 1)])
    def test_level_reaches_the_outstation(self, level, variation):
        """Level 2 sends analog output status in 16 bits (group 40 variation 2)."""
        config, simulation = self._simulation({"level": level})
        outstation = simulation.outstation
        assert outstation.level == (level or 2)
        master = Loopback(outstation.session(**config.session_options()))
        outputs = master.scan("outputs")
        analog = [o for o in outputs.objects if o.point is PointType.ANALOG_OUTPUT]
        assert analog and {o.variation for o in analog} == {variation}

    @pytest.mark.parametrize("flags, level", [(("--level", "4"), 4), (("--level2",), 2), ((), 2)])
    def test_level_flag_reaches_the_outstation_through_the_command_line(self, tables, flags, level):
        config = cli.configuration(_args("run", *flags))
        simulation = cli._build(config, cli._load_map(config))
        assert simulation.outstation.level == level
        assert simulation.outstation.level2 is (flags == ("--level2",))

    @pytest.mark.parametrize("value", [1, 5, 0, "2", 2.0, True, [2]])
    def test_level_outside_2_3_4_is_refused(self, value):
        with pytest.raises(ConfigError, match="level must be 2, 3 or 4"):
            DerConfig.from_mapping({"level": value})

    def test_command_line_refuses_a_level_outside_2_3_4(self, capsys):
        with pytest.raises(SystemExit):
            _args("run", "--level", "5")
        assert "invalid choice" in capsys.readouterr().err

    def test_level2_true_in_a_file_means_level_2(self):
        assert DerConfig.from_mapping({"level2": True}).level == 2
        assert DerConfig.from_mapping({"level2": False}).level is None

    def test_level2_true_with_another_level_is_refused(self):
        with pytest.raises(ConfigError, match="level2 conflicts with level"):
            DerConfig.from_mapping({"level2": True, "level": 3})

    def test_tables_and_composition_reach_the_map_loader(self, monkeypatch):
        seen = []
        monkeypatch.setattr(cli.load, "load", lambda *given: seen.append(given))
        config = DerConfig.from_mapping({"tables": "t.json", "composition": {"meters": 2}})
        cli._load_map(config)
        assert seen == [("t.json", Composition(meters=2))]

    def test_a_policy_that_does_not_fit_the_der_is_reported(self, tables, tmp_path, capsys):
        path = _file(tmp_path, {"event_policy": {"points": {"AI59999": {"class": 1}}}})
        assert cli.main(["points", "--config", path]) == 2
        assert capsys.readouterr().err.strip()

    @pytest.mark.asyncio
    async def test_run_serves_with_the_file_settings(self, tables, tmp_path):
        """Start the server from a file and read it as a master would."""
        listener = await asyncio.start_server(lambda reader, writer: None, "127.0.0.1", 0)
        port = listener.sockets[0].getsockname()[1]
        listener.close()
        await listener.wait_closed()
        path = _file(
            tmp_path,
            {"bind": f"127.0.0.1:{port}", "outstation_address": 10, "master_address": 3},
        )
        config = cli.configuration(_args("run", "--config", path))
        simulation = cli._build(config, cli._load_map(config))
        serving = asyncio.create_task(cli._serve(config, simulation))
        try:
            async with Master() as master:
                for _ in range(50):
                    try:
                        lab = await master.add(
                            "lab",
                            host="127.0.0.1",
                            port=port,
                            outstation_address=10,
                            master_address=3,
                            reconnect=None,
                        )
                        break
                    except OSError:
                        await asyncio.sleep(0.05)
                await lab.idle()
                assert lab.store.points(PointType.ANALOG_INPUT), "the integrity poll was answered"
        finally:
            serving.cancel()
            await asyncio.gather(serving, return_exceptions=True)
