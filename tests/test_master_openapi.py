"""The OpenAPI document, held to the service it describes.

A description of an API is only worth having while it is true. These tests
fail when an operation exists and is not described, when the document
committed is not the one the description builds, and when what the service
actually answers does not fit what the document says it answers.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
import pytest_asyncio
from profile_fixtures import for_reference_der
from test_master_service import JSON, _http

from py1815.master import openapi
from py1815.master.service import HttpServer, Service
from py1815.profile import der, load
from py1815.profile.model import Composition
from py1815.server import OutstationServer

DOCUMENT = openapi.build()


def _resolve(schema: dict[str, Any]) -> dict[str, Any]:
    while "$ref" in schema:
        prefix = "#/components/schemas/"
        assert schema["$ref"].startswith(prefix), schema["$ref"]
        schema = DOCUMENT["components"]["schemas"][schema["$ref"][len(prefix) :]]
    return schema


_TYPES: dict[str, Any] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def problems(value: Any, schema: dict[str, Any], where: str = "$") -> list[str]:
    """Why a value does not fit a schema: the part of JSON Schema this document uses."""
    schema = _resolve(schema)
    found: list[str] = []
    if "oneOf" in schema:
        fits = [option for option in schema["oneOf"] if not problems(value, option, where)]
        if not fits:
            return [f"{where}: {value!r} fits none of the alternatives"]
    if "const" in schema and value != schema["const"]:
        found.append(f"{where}: {value!r} is not {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        found.append(f"{where}: {value!r} is not one of {schema['enum']}")
    kind = schema.get("type")
    if kind == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [*found, f"{where}: {value!r} is not an integer"]
    elif kind == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return [*found, f"{where}: {value!r} is not a number"]
    elif kind is not None and not isinstance(value, _TYPES[kind]):
        return [*found, f"{where}: {value!r} is not {kind}"]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            found.append(f"{where}: {value} is below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            found.append(f"{where}: {value} is above {schema['maximum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            found.append(f"{where}: {value} is not above {schema['exclusiveMinimum']}")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                found.append(f"{where}: {name} is missing")
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                found += problems(item, properties[name], f"{where}.{name}")
            elif schema.get("additionalProperties") is False:
                found.append(f"{where}: {name} is not a property the document names")
            elif isinstance(schema.get("additionalProperties"), dict):
                found += problems(item, schema["additionalProperties"], f"{where}.{name}")
        if len(value) < schema.get("minProperties", 0):
            found.append(f"{where}: fewer than {schema['minProperties']} properties")
    if isinstance(value, list) and "items" in schema:
        for position, item in enumerate(value):
            found += problems(item, schema["items"], f"{where}[{position}]")
    return found


def _refs(node: Any) -> list[str]:
    if isinstance(node, dict):
        own = [node["$ref"]] if "$ref" in node else []
        return own + [reference for value in node.values() for reference in _refs(value)]
    if isinstance(node, list):
        return [reference for item in node for reference in _refs(item)]
    return []


class TestTheDocument:
    def test_every_operation_of_the_service_has_a_route_and_no_route_is_made_up(self):
        described = {
            path.removeprefix("/api/") for path in DOCUMENT["paths"] if path.startswith("/api/")
        }
        assert described == set(Service().operations)
        assert set(openapi.OPERATIONS) == set(Service().operations)

    def test_the_message_route_names_every_operation(self):
        message = DOCUMENT["paths"]["/api"]["post"]["requestBody"]["content"]["application/json"]
        assert set(message["schema"]["properties"]["op"]["enum"]) == set(Service().operations)

    def test_the_one_committed_is_the_one_the_description_builds(self):
        """Run ``python -m py1815.master.openapi --write`` after changing the description."""
        assert openapi.DOCUMENT.read_text(encoding="utf-8") == openapi.render()
        assert openapi.main(["--check"]) == 0

    def test_it_is_an_openapi_document(self):
        assert DOCUMENT["openapi"].startswith("3.1")
        assert {"title", "version"} <= set(DOCUMENT["info"])
        for path, item in DOCUMENT["paths"].items():
            for method, operation in item.items():
                assert method in ("get", "post"), path
                assert operation["operationId"] and operation["summary"], path
                assert "200" in operation["responses"], path
        identifiers = [
            operation["operationId"]
            for item in DOCUMENT["paths"].values()
            for operation in item.values()
        ]
        assert len(identifiers) == len(set(identifiers))

    def test_every_reference_leads_somewhere(self):
        schemas = DOCUMENT["components"]["schemas"]
        references = set(_refs(DOCUMENT))
        assert references, "the document does share its schemas"
        for reference in references:
            assert reference.removeprefix("#/components/schemas/") in schemas, reference

    def test_every_tag_used_is_described(self):
        described = {tag["name"] for tag in DOCUMENT["tags"]}
        used = {
            tag
            for item in DOCUMENT["paths"].values()
            for operation in item.values()
            for tag in operation["tags"]
        }
        assert used == described

    @pytest.mark.parametrize("name", list(openapi.OPERATIONS))
    def test_each_example_fits_the_parameters_it_is_an_example_of(self, name):
        operation = openapi.OPERATIONS[name]
        assert problems(operation["example"], operation["params"]) == []

    def test_a_stale_document_is_caught(self, tmp_path, monkeypatch, capsys):
        stale = tmp_path / "openapi.json"
        stale.write_text("{}\n", encoding="utf-8")
        monkeypatch.setattr(openapi, "DOCUMENT", stale)
        assert openapi.main(["--check"]) == 1
        assert "--write" in capsys.readouterr().err
        assert openapi.main(["--write"]) == 0
        assert openapi.main(["--check"]) == 0


class TestTheValidatorItself:
    """The checks below are only as good as this, so it is shown to refuse."""

    @pytest.mark.parametrize(
        ("value", "schema", "says"),
        [
            ({"a": 1}, {"type": "object", "required": ["b"]}, "b is missing"),
            ("x", {"type": "integer"}, "not an integer"),
            (True, {"type": "integer"}, "not an integer"),
            (5, {"type": "string"}, "not string"),
            ("z", {"enum": ["a", "b"]}, "not one of"),
            ([1, "x"], {"type": "array", "items": {"type": "integer"}}, "$[1]"),
            (7, {"oneOf": [{"type": "string"}, {"type": "null"}]}, "none of the alternatives"),
            ({"a": 1}, {"type": "object", "additionalProperties": False}, "not a property"),
            (0, {"type": "number", "exclusiveMinimum": 0}, "not above"),
            (70000, {"type": "integer", "maximum": 65535}, "above 65535"),
        ],
    )
    def test_it_says_what_does_not_fit(self, value, schema, says):
        (problem,) = problems(value, schema)
        assert says in problem

    def test_and_passes_what_does(self):
        schema = {"$ref": "#/components/schemas/Error"}
        assert problems({"kind": "request", "message": "no"}, schema) == []


@pytest_asyncio.fixture
async def live():
    """The service over HTTP, with a simulated DER to add."""
    point_map = load.resolve(for_reference_der(), Composition())
    simulation = der.build(point_map)
    outstation = OutstationServer(simulation.outstation.session(), bind="127.0.0.1:0")
    # Started to command, so that every operation's example is carried out.
    service = Service(allow_control=True)
    http = HttpServer(service, bind="127.0.0.1:0")
    await outstation.start()
    await http.start()
    try:
        yield service, http, outstation, point_map
    finally:
        await service.close()
        await http.stop()
        await outstation.stop()


async def _post(http: HttpServer, path: str, body: Any = None) -> tuple[int, Any]:
    sent = b"" if body is None else json.dumps(body).encode()
    status, headers, content = await _http(http.port, "POST", path, body=sent, headers=JSON)
    if headers.get("Content-Type") == "application/json":
        return status, json.loads(content)
    return status, content.decode()


def _documented(name: str) -> dict[str, Any]:
    responses = DOCUMENT["paths"][f"/api/{name}"]["post"]["responses"]
    return dict(responses["200"]["content"]["application/json"]["schema"])


#: The order the examples make sense in, against one outstation.
ORDER = [
    "add",
    "idle",
    "status",
    "profile",
    "scan",
    "read",
    "values",
    "events",
    "request",
    "operate",
    "write_time",
    "clear_restart",
    "freeze",
    "restart",
    "enable_unsolicited",
    "disable_unsolicited",
    "repeat",
    "trace",
    "capture",
    "clear",
    "disconnect",
    "connect",
    "remove",
    "stop",
]


class TestWhatTheServiceAnswers:
    def test_the_examples_are_tried_for_every_operation(self):
        assert sorted(ORDER) == sorted(openapi.OPERATIONS)

    @pytest.mark.asyncio
    async def test_each_documented_example_gets_the_answer_the_document_describes(self, live):
        service, http, outstation, point_map = live
        service.set_profile("lab", point_map)
        for name in ORDER:
            example = dict(openapi.OPERATIONS[name]["example"])
            if name == "add":
                # The document's address is one for documentation; this one answers.
                example |= {"host": "127.0.0.1", "port": outstation.port}
            if name == "read":
                example["points"] = {"ai": [der.AI_METER_FIRST + 4], "bi": "all"}

            status, answer = await _post(http, f"/api/{name}", example or None)

            assert status == 200, (name, answer)
            assert answer["ok"], (name, answer)
            assert problems(answer, _documented(name)) == [], name
            # And not vacuously: the result is the documented one, not a stray shape.
            assert problems(answer["result"], openapi.OPERATIONS[name]["result"]) == [], name

    @pytest.mark.asyncio
    async def test_a_refusal_is_the_documented_failure(self, live):
        _, http, _, _ = live
        status, answer = await _post(http, "/api/scan", {"outstation": "nobody"})
        assert status == 200 and not answer["ok"]
        assert problems(answer, {"$ref": "#/components/schemas/Failure"}) == []
        assert problems(answer, _documented("scan")) == []

    @pytest.mark.asyncio
    async def test_an_outstation_that_does_not_answer_is_a_documented_outcome(self, live):
        _, http, outstation, _ = live
        await _post(
            http,
            "/api/add",
            {
                "name": "deaf",
                "host": "127.0.0.1",
                "port": outstation.port,
                "outstation_address": 77,
                "response_timeout": 0.2,
            },
        )
        status, answer = await _post(http, "/api/scan", {"outstation": "deaf"})
        assert status == 200 and answer["ok"]
        assert answer["result"]["outcome"] == "timeout"
        assert problems(answer, _documented("scan")) == []


class TestTheRoutes:
    @pytest.mark.asyncio
    async def test_an_operations_route_and_the_message_route_answer_alike(self, live):
        _, http, _, _ = live
        _, by_route = await _post(http, "/api/status")
        _, by_message = await _post(http, "/api", {"id": 4, "op": "status"})
        assert by_route["result"] == by_message["result"]
        assert by_route["result"] == {"allow_control": True, "outstations": []}
        assert by_route["id"] is None and by_message["id"] == 4

    @pytest.mark.asyncio
    async def test_a_route_for_no_operation_is_not_found(self, live):
        _, http, _, _ = live
        status, _ = await _post(http, "/api/explode", {})
        assert status == 404

    @pytest.mark.asyncio
    async def test_parameters_are_an_object(self, live):
        _, http, _, _ = live
        status, said = await _post(http, "/api/status", [1, 2])
        assert status == 400 and "JSON object" in said

    @pytest.mark.asyncio
    async def test_an_operation_is_asked_with_post_and_as_json(self, live):
        _, http, _, _ = live
        status, _, _ = await _http(http.port, "GET", "/api/status")
        assert status == 405
        plain = {"Content-Type": "text/plain"}
        status, _, _ = await _http(http.port, "POST", "/api/status", body=b"{}", headers=plain)
        assert status == 400

    @pytest.mark.asyncio
    async def test_the_document_is_served_beside_the_console(self, live):
        _, http, _, _ = live
        status, headers, content = await _http(http.port, "GET", "/openapi.json")
        assert status == 200 and headers["Content-Type"] == "application/json"
        assert json.loads(content) == DOCUMENT
